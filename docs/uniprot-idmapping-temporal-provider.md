# UniProt ID Mapping temporal provider proof

This pack is the first provider-neutral proof of an admitted asynchronous
provider lifecycle. It is deliberately narrow: one UniProt ID Mapping job
surface behind the unchanged `https://rest.uniprot.org` authority.

The task, agent, verifier, reward, and training loop stay outside Datalox. The
pack contributes only resettable provider behavior and trusted state evidence.

## Admitted surface

| Operation | Observed provider behavior represented locally |
| --- | --- |
| `POST /idmapping/run` | accepted UniRef100 submission |
| `GET /idmapping/status/{job_id}` | `RUNNING`, terminal `303` result redirect, unknown-job `404` with `messages` and `url` |
| `GET /idmapping/uniref/results/{job_id}?format=json&size=1` | terminal `200` result availability and unknown-job `404` with `messages` and `url` |

The lifecycle observations are selected facts from three authoring sessions,
not a manufactured contiguous transcript. Every fact carries its actual
provider `Date` timestamp and a digest referring to privately retained source
bytes. The first three source manifests were built post hoc and are unsigned;
the separate status-failure receipt was written by the status-only authoring
mode during acquisition and is also unsigned. No raw provider payload,
provider-generated job identifier, or submitted identifier is public. The
UniRef100 request identity and duplicate relation are bound to the exact
retained identifier-set artifact by an unsigned post-hoc restricted record;
raw HTTP request bodies were not retained, so the semantic equality relation
remains explicitly investigator-attested.

The retained submit and duplicate responses are byte-equal, but raw request
bytes were not retained. That duplicate relation remains an investigator note
and is not promoted as provider-grounded duplicate behavior.

Core admission still exercises local invalid-write and exact-repeat behavior.
Those two probes are explicitly `G1_SCHEMA_INSTANTIATED` authored completeness,
so the aggregate `POST /idmapping/run` operation is admitted at G1. Its submit
success is separately observed at G3. Status and UniRef-result operations remain
G3 because every behavior they claim is bound to retained provider evidence.

## Provider-local time

The provider runtime declares both `clock` and `scheduled_events`. A trusted
controller can inspect or advance this provider-local clock:

```text
GET  /v1/providers/uniprot/time
POST /v1/providers/uniprot/time/advance
     {"target":"2026-09-02T00:01:00Z"}
```

These routes are absent from the agent data plane. Advancing time delivers only
declared provider events, validates admitted invariants inside the same state
transaction, and returns event IDs, kinds, and delivery times without private
event payloads. Reverse time fails. Repeating the current target is a true
no-op. Reset restores the seed clock and removes jobs and scheduled events;
resume preserves a pending schedule.

This clock is independent of Composition Pack
`composition_delivery_time`. The latter schedules cross-provider edge
delivery and never advances provider-native time.

## Grounded and authored boundaries

Grounded against UniProt public production release `2026_03`, deployment
`02-September-2026`:

- method and route relations for the three admitted operations;
- UniRef100 submission, pending status, terminal UniRef redirect and result
  availability;
- separately captured unknown-status and unknown-UniRef-result `404` shapes;
- observed status codes and the declared response relations above.

The retained UniParc premature-result trace and ChEMBL invalid-source response
are not executable claims in this pack because their exact request identities
are not durably retained.

Self-authored locally:

- the deterministic 60-second logical completion point;
- generated local job identifiers;
- mapping fixture inputs and outputs;
- provider-shaped error text;
- local exact-repeat reuse, informed by the unpromoted investigator-attested
  semantic duplicate relation;
- local reset and resume mechanics.

The pack does not claim the provider's wall-clock latency distribution,
provider reset equivalence, rate limits, concurrent submission behavior,
webhooks, retry windows, timeout/unknown completion, broader UniProt access
policy, or raw response-byte equivalence.

## Reproduce the local proof

These commands perform no provider access:

```bash
python scripts/providers/check-uniprot-idmapping-lifecycle.py
pytest -q tests/test_provider_temporal_runtime.py \
  tests/test_uniprot_idmapping_provider.py
```

The checker runs the admitted lifecycle twice with a functional reset between
cycles. It proves that ordinary status polling does not advance provider time,
one declared completion event changes the job to terminal exactly once,
same-target advance is stable, and reset restores the initial capabilities and
observations.

Provider access remains authoring-only. The lifecycle acquisition utility now
permits only one explicit `--status-failure-only` read, rejects every writable
job argument, requires a new private receipt directory outside the repository,
and retains an unexpected response as a failed private receipt without
retrying. The obsolete generic writable mode was removed. Any future writable
acquisition requires a separately reviewed, route-aware, raw-retaining utility
for its exact target family.
