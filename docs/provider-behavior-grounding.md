# Provider Behavior Grounding

Provider core completeness and provider behavior grounding are different
milestones.

Private provider execution order is deliberately kept outside this public
grounding contract.

- **Core completeness** means the declared provider scope accounts for every
  selected operation family and capability kind. Mutable operations must have
  executable local shadows or explicit denials.
- **Behavior grounding** means provider-sandbox evidence establishes the
  observable state transition, duplicate or idempotency behavior, failure
  contract, related-object effects, and resulting reads for a behavior
  program.

A provider can be core-complete without any provider-observed writes. World
admission and replay completion also do not imply behavior grounding.

## Sandbox-First Acquisition Rule

Do not recreate a provider that already operates a useful sandbox merely
because Datalox can mock its API.

For providers such as Stripe, the provider-managed sandbox is the preferred
source of business-logic evidence. Datalox should integrate the sandbox,
capture complete behavior programs, and compile the captured behavior into
reusable fuel. It should not first implement a second provider sandbox from
documentation.

Use this routing decision before provider implementation:

1. **Adequate managed sandbox or developer tenant:** build or reuse a thin
   sandbox connector. Execute declarative behavior recipes through official
   APIs, SDKs, CLIs, test helpers, simulations, or fixtures.
2. **Disposable self-hosted reference system:** deploy the reference system,
   connect the generic capture path, and treat the deployment as the behavior
   oracle.
3. **No usable sandbox or reference system:** use authorized captures,
   official-source contracts, and a bounded local model. Keep every unobserved
   transition explicit.

An adequate sandbox normally provides most of:

- isolated test data and sandbox-specific credentials;
- stable API or tool access;
- official fixtures, test helpers, simulations, or controllable clocks;
- observable request IDs, events, jobs, or webhook delivery;
- a cleanup, namespace, tenant-recreation, or reset boundary;
- enough documented similarity to the behavior being modeled.

The reusable integration target is:

```text
provider sandbox
  -> official API / SDK / CLI / test helpers
  -> generic Datalox capture transport
  -> before/write/duplicate/failure/after + events/logs
  -> sanitized behavior program
  -> local fuel and provider-versus-replica tests when needed
```

A sandbox connector should declare only provider-specific facts:

- authentication source and exact sandbox-account fingerprint;
- API version and imported operation surface;
- official fixtures, helpers, and temporal controls;
- event, webhook, request-log, and job collectors;
- run-scoped naming, cleanup, and reset strategy;
- sandbox limitations and production differences.

The generic authoring layer should own sequencing, generated-ID binding,
idempotency, polling, request/response capture, secret handling, evidence
validation, and behavior-program compilation. Do not repeat those mechanisms
in a bespoke runner for every provider.

### When Local Reimplementation Is Justified

Reimplement sandbox-backed behavior only when a named requirement demands it:

- credential-free or offline evaluation and post-training at high volume;
- deterministic reset, isolation, or parallelism the sandbox cannot provide;
- provider rate limits, cost, availability, or tenant supply block the work;
- the sandbox omits a core transition or materially differs from the target;
- rare failures, concurrency, timeout ambiguity, or recovery cannot be
  triggered or observed;
- a customer or partner explicitly requires a distributable local substitute.

Even then, capture the sandbox first and implement only the evidenced slice.
Do not attempt a full provider clone by default.

Stripe is the reference case for this rule. Its isolated Sandboxes,
sandbox-specific keys, CLI/test fixtures, test helpers and simulations, and
Workbench request/event/webhook observations should feed a Stripe connector.
The current hardened Stripe authoring runner defines useful safety and evidence
requirements, but it is bridge code to the generic connector—not a template
for one runner per company.

Official reference points:

- [Stripe Sandboxes](https://docs.stripe.com/sandboxes)
- [Stripe testing use cases](https://docs.stripe.com/testing-use-cases)
- [Stripe CLI event triggers](https://docs.stripe.com/stripe-cli/triggers)
- [Stripe Workbench](https://docs.stripe.com/workbench/overview)

## Promotion Unit

The promotion unit is a complete behavior program, not an endpoint or an
isolated response.

For a mutating POST, a promotable program normally contains:

```text
read relevant state
-> send the exact reviewed write with a unique idempotency key
-> repeat the same request with the same key
-> send changed parameters with that same key
-> read the resulting and related state
```

For a DELETE, it contains:

```text
read relevant state
-> delete
-> repeat the delete
-> retrieve the deleted resource
-> read any related state
```

Invalid transitions require an exact provider error oracle and a later read
that proves the intended post-state. A generic error type is not enough.

Programs are promoted atomically. A partial transcript, a redacted response,
an unknown write completion, or an underasserted state change leaves the whole
program unobserved.

## Evidence Requirements

Committed provider evidence must let the offline checker independently
recompute its claims:

- exact reviewed request identity and account preflight;
- strict response status, media type, framing, and complete body bytes;
- raw response-body length and hash;
- duplicate-free, finite UTF-8 JSON parsing;
- zero-redaction secret scan for the current self-contained evidence lane;
- canonical body derivation from those exact raw bytes;
- exact generated-ID bindings and provider object types;
- operation-specific errors and asserted before/after state;
- no retry or resume after unknown write completion.

If exact raw response bytes contain a secret or require redaction, the current
lane fails closed. A digest of discarded raw bytes is not sufficient proof of
raw-to-sanitized derivation.

Provider writes remain outside the Datalox runtime. They may be performed only
by a separate, manually approved authoring utility against an exact sandbox or
test-mode account. Runtime live writes must remain inexpressible.

Complete provider evidence must be durable. In the private superset, retain the
exact reloadable capture and every digest-pinned static input it needs under a
declared restricted data path. A normalized summary that points only to an
operator laptop, `/tmp`, or an unspecified external evidence store is not a
completed program. The public-source builder excludes restricted captures; it
does not justify discarding them.

## Current Specialized Harvest Wave

The active implementation work is no longer centered on Stripe. The checked
four-provider wave applies the shared authoring and packaging contracts to:

- OpenLMIS public-health supply-chain operations;
- GS1 EPCIS traceability against a pinned FasTnT reference;
- a connected TM Forum order, activation, assurance, and recovery workflow;
  and
- the Opentrons virtual protocol and run lifecycle.

The separately promoted Hamilton STAR lane uses PyLabRobot `0.2.1` as a
device-free reference system. Its standard eight-channel slice is
core-complete: setup, stop, tip pickup/drop, aspiration, dispense, and the
corresponding state reads all execute through one task-free provider pack. All
six writes and selected native failures were observed against
`LiquidHandlerChatterboxBackend`. This is G2 local reference execution, not
physical Hamilton hardware evidence. See
[PyLabRobot-Backed Hamilton STAR Provider](pylabrobot-hamilton-star-provider.md).

These lanes intentionally have different outcomes. A lane may contain complete
reference-observed programs, a fully executable but mismatching differential,
or a precise capture blocker. None of those should be flattened into one
“supported” flag. The private superset maintains the operation-level status,
reset evidence, package proof, and exact blockers in its classified artifacts.

OpenLMIS no longer has a per-step actor execution blocker. Its 11 complete
retained programs all execute through the provider-neutral differential target
with explicit principal contexts. The five-step
`notification.update_contact_details` program—administrator read, supervisor
denial, administrator write, duplicate, and read-after-write—passes exactly.
The other ten report their concrete response or state mismatches. This is one
bounded behavior-equivalence result, not provider-wide faithfulness; nine
partial programs and functional reset equivalence remain incomplete.

Stripe remains a narrow construction-machine regression and a useful example
of the sandbox-first rule below. Reproducing its already capable playground is
not the current provider-data priority.

## Stripe Checkpoint

As of 2026-08-05, `stripe_billing_ops_v0` has:

- 22 behavior programs mapping all 65 selected operations and all 38 writes;
- nine bounded authoring candidates;
- one promotable four-step program:
  `idempotency_parameter_conflict`;
- zero provider-observed writes;
- no complete or partial provider capture.

The engineering spine for the one promotable program is now executable:
validated acquisition compiles to a reference trace, runs an explicit
provider-versus-world differential twice across fresh resets, requires world
admission, builds a canonical gated OCI package, and produces content-hashed HUD
and Harbor adapters over that same package. See
[Stripe Engineering Proof](stripe-engineering-proof.md).

That implementation is not provider evidence. Its offline integration test
uses a synthetic transport around the real authoring runner. Until the reviewed
test-mode capture exists and `proof.json` passes, the selected program remains
capture-ready rather than provider-grounded.

The other 21 programs remain explicit blockers because they lack an exact
duplicate, failure, state-delta, supporting-object, eventual-consistency, or
zero-redaction oracle.

The independently reviewed authoring snapshot is:

| Artifact | SHA-256 |
| --- | --- |
| `evidence/official_source_pins.json` | `b7a6b50d9c1c0b618269d1a95fcc613cba9fd719366dd2414bfd2d7ebe9967ce` |
| `evidence/testmode_transition_manifest.json` | `59c34ea273c707d2c191f8c7ca6f72c4366e422f3da3da922d169d4c078e8445` |
| `scripts/providers/check-stripe-testmode-transition-evidence.py` | `7bf04f2d565f5686037477931537fc32af0c73a5d8798bdd226d0176d521ce00` |
| `scripts/providers/capture-stripe-testmode-transitions.py` | `3cd576baead6b64e9e4fa1697337b3611182520a27780bdf4c879ec8abb84500` |

Two independent offline reviews passed those exact bytes: one for capture
safety and one for evidence semantics. That approval is invalid after any
change to a pinned artifact.

No Stripe request can be made from the current checkpoint because the workspace
does not contain `DATALOX_STRIPE_TEST_SECRET_KEY` or an expected test account
ID. Never paste the secret key into a document, command history, issue, or chat.
Load it into the process environment through an approved secret mechanism and
provide the non-secret exact `acct_...` test account ID separately.

Before an approved capture, recompute the four hashes above and obtain two new
reviews if any differ. The runner requires:

```text
--execute-reviewed-testmode-writes
--expected-runner-sha256 sha256:<reviewed runner digest>
--expected-manifest-sha256 sha256:<reviewed manifest digest>
--expected-source-pins-sha256 sha256:<reviewed source-pins digest>
--expected-account-id acct_<reviewed test account>
```

After capture, run the offline checker with the exact expected account ID.
Passing the one-program capture gate proves only that program. It does not make
Stripe behavior-grounded, does not validate the remaining 37 writes, and does
not authorize local behavior corrections outside the observed evidence.

## Completion Criterion

A provider may be labeled behavior-grounded only when:

1. every selected mutable operation belongs to a complete behavior program;
2. every program has provider-observed success, duplicate/idempotency,
   provider-native failure, and before/after evidence;
3. related objects, pagination, asynchronous completion, and ordering are
   observed where the provider exposes them;
4. the local replica passes a normalized provider-versus-replica differential
   suite;
5. reset after arbitrary mutations restores equivalent observable behavior;
6. independent review finds no unsupported behavior or verifier claim; and
7. runtime live writes remain inexpressible.
