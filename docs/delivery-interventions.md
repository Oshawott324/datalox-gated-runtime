# Delivery Interventions

Delivery interventions let a consumer run the same provider-backed task with a
fixed adversarial delivery policy off and on. They are an environment control,
not evidence about the provider.

```text
admitted Provider Runtime
  -> base response and provider ledger
  -> controller-fixed delivery intervention
  -> ASGI transport attempt on the agent connection
  -> separate intervention trace
```

The provider runtime executes unchanged and retains its original operation-level
grounding. The intervention layer cannot add evidence to a provider claim or
change admission. Its trace binds the provider, policy identifier, version and
digest, episode seed, logical request index, counterfactual decision, exact
validated action, optional base event and response digest, and selected
transport observation. The trace field is named `delivered` for schema
continuity; v2 qualifies it with transport progress and always leaves client
receipt unknown.

Every session also binds the exact release version, selected profile, bundle
version, release-config digest, provider-runtime digest, admission digest,
operation-contract digest, and the digest of its non-empty admitted-read
operation set. The intervention session rejects direct calls outside that set
before the policy runs or the logical request index advances. The transparent
gateway sends admitted writes directly to the base runtime, unchanged and
unindexed; unknown operations receive the base runtime's ordinary rejection.

## Paired execution

An experiment creates two isolated provider sessions from the same admitted
release and reset profile:

```text
off: same task + provider state + policy + seed -> base observation
on:  same task + provider state + policy + seed -> intervened observation
```

`off` still evaluates and records the counterfactual decision. It returns the
base `GateResponse` unchanged. The mode-independent intervention event ID joins
the corresponding off/on records; `enabled` and `applied` express the mode.
Agent behavior may diverge after the first changed observation, so fixed request
sequences establish response-level identity while paired rollouts measure the
agent-level consequence.

The mode, seed, provider release, and policy are trusted operator inputs fixed
when the isolated session is created. They are unavailable on the provider data
plane. Calls carrying the reserved `x-datalox-*` namespace and calls outside the
admitted provider surface bypass the intervention layer and receive the base
runtime's normal rejection. Admitted writes also bypass the read-only v1
intervention layer and execute through the base runtime normally.

## Policy ownership

The consumer owns the deterministic decision policy and its distribution.
Datalox calls the policy exactly once per admitted logical provider request and
applies the returned action exactly. It does not retry, resample, smooth,
normalize, repair, or select a substitute intervention.

The checked static policy format is
[`delivery-intervention-v1.schema.json`](../schemas/delivery-intervention-v1.schema.json).
One policy can declare exact schedules for multiple seeds. `policy_sha256`
binds the complete policy while `seed` selects one schedule, so policy identity
and episode selection remain distinct.

## V1 actions

- `quota_response` is an exact controller-declared pre-dispatch HTTP `429`.
  The provider runtime is not invoked and the trace records that no base event
  exists. For an admitted route, this pre-dispatch intervention occurs before
  provider-native identity evaluation and can therefore mask the base provider's
  authentication response. Experiments requiring provider authentication first
  must use a post-response action instead.
- `json_type_drift` replaces one existing JSON-pointer value after verifying
  its declared source type and replacement type.
- `repeat_page` delivers the full body of a named earlier base response from
  the same admitted operation. It does not decode, increment, or manufacture a
  provider cursor.

V1 applies only to admitted read operations. A timeout action is unsupported
and fails configuration loading. Returning a JSON `504` or raising an ASGI
exception would not reproduce a client-observed transport timeout. Timeout
intervention requires a later transport-layer implementation that deterministically
holds or terminates the socket beyond the caller's deadline and records the
absence of a delivered HTTP response.

## V2 write-time transport failures

V2 preserves v1 and adds one narrow transport action for admitted reads and
writes:

```json
{"kind": "no_response", "phase": "pre_dispatch"}
```

or:

```json
{"kind": "no_response", "phase": "post_dispatch"}
```

`pre_dispatch` durably records the controller decision before provider dispatch,
does not invoke the provider, and records equal before/after provider-state
digests. `post_dispatch` durably records the decision, invokes the provider
exactly once, binds the provider event, complete base response, and before/after
state digests, then sends no HTTP response start or body. The controller knows
whether the provider state changed and whether a base response completed; the
agent only knows that its request did not complete.

The behavior-state digest excludes call/audit receipts. For world-backed packs
it includes logical time, business state, artifacts, scheduled events,
conversations, and handoffs while excluding `events` and `verifier_events`; for
gate-config packs it covers shadow state. A read or denied write therefore
remains `unchanged` even though its controller evidence ledger grows.

The ASGI data plane waits for a real client disconnect. It does not return a
JSON `504`, raise a synthetic provider error, retry, or hold the provider lock
while waiting. Off mode evaluates the same `(policy, seed, request_index)`
decision and returns the exact base response.

V2 decisions and outcomes use a SQLite journal with full synchronous commits.
The decision commit precedes dispatch, the base-outcome commit precedes ASGI
response sending, and a second durable transition records completion only
after ASGI accepts the response start and complete body. Until that callback,
the response remains `transport_pending`; process loss terminalizes the lease
with unknown client completion and requires reset. The trace says
`asgi_send_completed`, meaning the server accepted the exact response start and
body; it never claims that the client received or processed the response.
Each event binds an evidence-safe digest of method, authority, path,
query, body, and every non-secret header name/value. The provider bundle's
exact identity policy removes standard secret headers and its declared header,
cookie, or query credential selectors before hashing. That policy digest is
part of the durable session binding, so idempotency and other behavioral
headers remain distinguishable while credential values never enter the
journal.
Provider-native HTTP failures pass through unchanged when the policy has no
scheduled transport action.

Reset returns `409` while any response or no-response transport outcome remains
pending. A normal response leaves the set only after exact ASGI send completion;
a no-response action leaves it after a real client disconnect. If a completion
record fails, the session records a best-effort
terminal failure, removes the genuinely disconnected client from the active
pending count, and permits trusted reset. A policy, state-observation, or
decision-journal failure before dispatch returns a stable structured `503`,
records `not_dispatched`, and never invokes the provider. A reset failure
terminally latches the session, and trusted shutdown
durably aborts outstanding transports while still closing every provider
resource. Resuming a journal after process loss terminalizes any formerly
pending transport and any decision record that lacks a durable base outcome,
then requires reset. A decision-only record marks provider dispatch, completion,
and resulting state as unknown because process loss may have happened before,
during, or after the single base call. Its old client connection cannot be
silently reconstructed. The trace represents this three-valued dispatch state
as `base.invoked: true | false | null`, where `null` means unknown.

The checked configuration and trace shapes are:

- [`delivery-intervention-v2.schema.json`](../schemas/delivery-intervention-v2.schema.json)
- [`delivery-intervention-trace-v2.schema.json`](../schemas/delivery-intervention-trace-v2.schema.json)

An admitted TLS runtime accepts one controller-only config per provider:

```bash
datalox-gate intercept serve-admitted \
  --bundle provider-runtime \
  --admission provider-admission.json \
  --release-config provider-release.json \
  --delivery-intervention provider_id=delivery-intervention-v2.json \
  --run run --prepared
```

The agent still calls the exact provider URL. It cannot select the policy,
seed, mode, provider lease, or control operation.

## Evidence and reset

Provider evidence remains available through:

```text
GET /v1/providers/{provider_id}/export
```

The separate intervention export is controller-only:

```text
GET /v1/providers/{provider_id}/delivery-interventions/export
```

Its strict shape is
[`delivery-intervention-trace-v1.schema.json`](../schemas/delivery-intervention-trace-v1.schema.json).

### Execution and observable effect are separate claims

`applied` states that the policy action executed. It does not state that the
agent saw anything different, because an action can execute and still deliver a
response equal to the base one: a repeated page can name the page the provider
was about to return anyway.

`observation_changed` carries the observable effect, so counting delivered
interventions does not require recomputing hashes:

| Field | Meaning |
| --- | --- |
| `base_sha256` | canonical digest of the base provider response, `null` when no base call was made |
| `delivered_sha256` | canonical digest of the response handed to the agent, `null` when nothing was delivered |
| `observation_changed` | those two digests differ |

The same digests remain available in their original places, `base.response_sha256`
and `delivered.response_sha256`; the event-level pair exists so that the
comparison can be queried without walking into both objects. The independent
auditor rejects any disagreement between the event-level and nested digests.

The digest covers the canonical JSON encoding of `{status_code, headers, body}`,
not raw transport bytes. Three cases follow from the definition:

- a pre-dispatch action such as a quota response has no base digest, so the
  delivered observation always counts as changed;
- an event with no action, and an `off` event that records only the
  counterfactual decision, delivers the base response and counts as unchanged;
- a terminal failure delivers no observation at all and records `null`.

An applied action with `observation_changed` false is an observational no-op:
correct execution, no consequence for the agent. Statistics over `applied`
alone overstate what a run exercised.

Reset clears the logical request index, remembered base pages, and intervention
trace together with the provider reset. The operator-fixed mode, policy, and
seed remain unchanged.

Policy selection, base dispatch, exact action application, and evidence writes
fail closed. A failure consumes and records that logical request index, links
any base event that already occurred, and terminally latches the intervention
session. Later provider calls are refused until trusted reset; execution never
continues with an untraced gap.
