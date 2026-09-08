# Provider State Profiles

A Provider State Profile is a task-independent, operator-selected reset state
for one exact Provider Runtime. It makes tenant depth a versioned and testable
part of Datalox fuel without inventing a universal business-object schema.

The provider keeps its native state shape. Datalox records the provenance,
rights, construction method, reachable operation surface, relationships,
lifecycle coverage, pagination behavior, mutation/reset probes, temporal
boundary, and known gaps around that opaque state.

## Boundary

A state profile may contain provider objects and history that the agent can
discover through ordinary provider calls. It must contain none of:

- task objectives or success criteria;
- evaluator, oracle, or verifier ground truth;
- prefetched observations that bypass a provider action; or
- an agent-selectable profile or reset control.

The operator selects the immutable Provider Release profile before a rollout.
Each rollout lease receives a private copy and the trusted controller alone can
reset or export it.

## Contract

`datalox_provider_state_profile_v1` binds:

- `profile_id`, provider ID, bundle version, source episode, and exact seed
  digest;
- a digest-pinned, task-free base seed, construction trace, and its
  trusted-controller principal;
- provider-native state families with exact cardinality, value origin,
  grounding level, sources, and required lifecycle values;
- referential-integrity checks across native provider collections, including
  provider-specific target-ID pointers and minimum checked-link coverage;
- read-only reachability and permission probes;
- complete page- or cursor-based traversal with a declared unique-item count,
  provider-native response assertions, and no repeated IDs;
- a real mutation followed by reset and repeated observations;
- provider-local time and declared pending-work locations; and
- distribution rights and explicit known gaps.

Construction methods are explicit:

- `compiled_seed_v1`: the state is supplied directly;
- `provider_operation_trace_v1`: all final state is produced through provider
  operations from the recorded base state; and
- `seed_plus_provider_operation_trace_v1`: authored or authorized base/master
  data is combined with transactional history produced through provider
  operations.

Value provenance is separate from behavioral grounding. A self-authored
facility name can sit inside a lifecycle whose status transition is grounded
by an official reference service; the profile must say both facts rather than
promoting the value itself as provider-observed.

## Admission and packaging

Build the task-free runtime from the selected state, execute state admission,
then bind both state documents into the same OCI profile as the runtime and
operation admission:

```bash
datalox-gate provider build-runtime \
  --source-world ./envs/openlmis_supply_chain_v0 \
  --seed-file ./envs/openlmis_supply_chain_v0/state-profiles/regional-network-v1/seed.json \
  --provider-id openlmis \
  --authority openlmis.example \
  --out /tmp/openlmis-runtime

datalox-gate provider admit-state \
  --bundle /tmp/openlmis-runtime \
  --profile ./envs/openlmis_supply_chain_v0/state-profiles/regional-network-v1/profile.json \
  --out /tmp/openlmis-state-admission.json

datalox-gate provider release-build \
  --profile regional-network-v1 /tmp/openlmis-runtime /tmp/openlmis-provider-admission.json \
  --state-profile regional-network-v1 \
    ./envs/openlmis_supply_chain_v0/state-profiles/regional-network-v1/profile.json \
    /tmp/openlmis-state-admission.json \
  --release-version openlmis-regional-network-v1 \
  --out /tmp/openlmis-release
```

State admission first replays every construction operation from the retained
base seed, matches each response digest and state-change relation, and requires
the result to equal the shipped reset seed. It then
executes the declared observations and pagination, performs the mutation,
resets, repeats the observations, and repeats the whole run in a new runtime.
The two execution digests must match. The OCI profile carries a complete
`state/` subtree: `profile.json`, `admission.json`, the base seed, and the
construction trace. The release config binds the profile and admission
digests; those documents bind the two construction assets. A materialized
release can therefore rerun State Admission without access to the authoring
checkout. Profiles without state digests remain explicitly state-unadmitted
rather than inheriting a tenant-depth claim.

## First admitted fixture

The OpenLMIS `regional-network-v1` profile is the first complete public fixture.
Its task-free `seed.json` lives outside the reference world's task episode list;
compilation accepts it through `--seed-file`, then copies it into the immutable
Provider Runtime. This keeps provider state independent from downstream tasks
and their reference trajectories.
Its values and cardinalities are self-authored. It contains five facilities,
eight provider users, seven requisitions across six statuses, orders across
four statuses, linked shipments and proofs of delivery, stock records, and
operational history. Ninety-six real provider-operation invocations construct
the transactional portion. Its three-page requisition traversal, relationship
checks, authorization denial, state mutation, reset, and fresh-run equivalence
are executable admission criteria.

This fixture proves the state-profile machinery. It does not claim that its
tenant distribution matches a production OpenLMIS deployment. Future profiles
should be sampled from authorized sources often enough to justify their stated
freshness and distribution claims.
