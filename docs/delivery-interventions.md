# Delivery Interventions

Delivery interventions let a consumer run the same provider-backed task with a
fixed adversarial delivery policy off and on. They are an environment control,
not evidence about the provider.

```text
admitted Provider Runtime
  -> base response and provider ledger
  -> controller-fixed delivery intervention
  -> observation delivered to the agent
  -> separate intervention trace
```

The provider runtime executes unchanged and retains its original operation-level
grounding. The intervention layer cannot add evidence to a provider claim or
change admission. Its trace binds the provider, policy identifier, version and
digest, episode seed, logical request index, counterfactual decision, exact
validated action, optional base event and response digest, and delivered
observation.

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
Reset clears the logical request index, remembered base pages, and intervention
trace together with the provider reset. The operator-fixed mode, policy, and
seed remain unchanged.

Policy selection, base dispatch, exact action application, and evidence writes
fail closed. A failure consumes and records that logical request index, links
any base event that already occurred, and terminally latches the intervention
session. Later provider calls are refused until trusted reset; execution never
continues with an untraced gap.
