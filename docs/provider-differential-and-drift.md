# Provider Differential and Drift

This document defines how Datalox measures whether one immutable Provider
Release still reproduces one authorized provider behavior program. It adds a
faithfulness claim without adding provider access to evaluated-agent runtime.

## Evidence loop

```text
authorized provider source
  -> digest-pinned behavior-harvest connector and recipe
  -> complete grounding measurement
  -> binding-aware execution against an immutable Provider Release
  -> differential attestation

the same authorized source at a later date
  -> the same digest-pinned recipe
  -> candidate grounding measurement
  -> baseline/candidate drift comparison
  -> candidate/Provider Release differential
  -> append-only release assessment
```

The runtime side remains offline. Only the separate `datalox-author` process
may contact a provider. An evaluated agent cannot select an upstream, provide a
live forwarding address, invoke reset, or read the assessment store.

## Implemented v1 surface

The loop is split into nine independently testable pieces:

1. `datalox-author harvest` is the only generic live-source entry point. It
   accepts digest-pinned connector, recipe, engine, and static inputs; sandbox
   writes require `--execute-sandbox-writes`.
2. `datalox_provider_grounding_measurement_v1` binds the observation time,
   rights decision, capture, source contracts, harvest engine, and exact
   compiled-program artifact.
3. `datalox_compiled_behavior_program_v1` preserves the original operations,
   declared generated-value bindings, actor context, failures, state
   relations, and every asynchronous polling attempt.
4. `ProviderReleaseTarget` materializes an immutable registry release/profile
   and executes the original method, path, query, body, headers, operation ID,
   and explicitly bound provider principal at the selected HTTPS authority.
5. `provider differential` runs the program initially, again after resetting
   the mutated instance, and once in a separately materialized instance.
6. `provider drift compare` compares two source measurements with typed status,
   header, body, state, duplicate, native-failure, pagination, asynchronous,
   and provider-version differences.
7. `provider drift assess` derives `current`, `provider_drift_detected`,
   `replica_mismatch`, or `reacquisition_blocked`; freshness is derived from a
   trusted `as_of` rather than stored as mutable state.
8. `provider assessments` publishes assessments in an append-only,
   content-addressed release/profile/program registry and provides deterministic
   `list`, `latest`, and trusted-time `status` reads.
9. The retained OpenLMIS contact-update capture exercises one real write
   lifecycle through an admitted task-free OCI Provider Release. Its restricted
   evidence test proves exact responses and functional reset; the public test
   suite exercises the same machinery with redistribution-cleared fixtures.

## Existing artifacts remain authoritative

Behavior-harvest v3 remains the acquisition format. Its connector pins the
source boundary, provider release, authentication contexts, engine bytes,
limits, and reset claim. Its recipe defines the ordered before, successful
mutation, duplicate, native failure, resulting-state, supporting, and polling
steps. Its capture contains the sanitized provider observations and generated
value bindings.

The differential layer does not introduce another capture or provider-state
schema. It compiles the exact retained capture and executes the same native
operations against a materialized Provider Release profile.

## Grounding measurement

A `datalox_provider_grounding_measurement_v1` document binds an observation
time and rights decision to the exact capture, connector, recipe, harvest
engine, and compiled program. When the source exposes a reset receipt, its
digest is included too. A complete measurement may enter comparison. An
incomplete acquisition keeps `compiled_program_sha256` null, cannot enter a
release differential, and cannot become provider truth.

Provider-derived payloads retain their distribution label. A public
measurement may expose reviewed metadata and digests without exposing a
restricted capture.

## Release differential

The target is the immutable Provider Release profile that a consumer installs,
not a reference world directory. Each captured request keeps its provider path,
method, query, body, operation identity, and explicitly selected principal
context. The selected release authority supplies the exact HTTPS authority.
There is no path remapping or response post-processing.

Generated provider values compare through the bindings declared in the
behavior recipe. Other values compare exactly. Response status, safe headers,
body, duplicate behavior, failure behavior, readback, state relations,
pagination, and every captured polling attempt are part of the result.

A passing `datalox_provider_differential_attestation_v1` requires:

1. one execution against a fresh materialized runtime;
2. the same execution after resetting the mutated runtime;
3. one execution against another freshly materialized runtime;
4. equal initial state digests, response transcripts, and final state digests;
5. every declared program step and attempt to execute; and
6. every comparison to pass.

Normal Provider Admission and differential attestation are separate. Provider
Admission proves that the local module satisfies its declared local operation
contract. Differential attestation proves equivalence to one exact provider
observation.

## Temporal behavior

Polling comparison retains every attempt, including attempt number, status,
safe headers, intermediate provider state, and terminal provider state. Raw
wall-clock acquisition elapsed time is metadata rather than exact provider
behavior. A temporal completion claim requires explicit minimum and maximum
bounds in the reviewed program. A target with a provider-local clock advances
that clock only through trusted controller code.

## Drift assessment

Source drift compares two complete grounding measurements of the same exact
program. The comparator first requires matching provider, program, recipe,
source boundary, and seed. Generated values are converted to declared binding
placeholders before comparison.

Typed differences are reported as status, safe-header, response-body,
state-relation, duplicate, native-failure, pagination, or asynchronous-sequence
changes. A changed recipe is `program_changed`, not provider drift. An
incomplete re-acquisition is `reacquisition_blocked`, not a provider claim.

The same assessment then compares the candidate measurement to the immutable
Provider Release. The derived status is one of:

- `current`: provider behavior is unchanged and the release passes;
- `provider_drift_detected`: the candidate provider behavior differs;
- `replica_mismatch`: the provider baseline is stable and the release fails;
- `reacquisition_blocked`: acquisition or source reset did not complete; or
- `stale`: no complete assessment falls inside the declared freshness window.

Drift never edits a release. An accepted behavior change produces a reviewed
capture, a corrected runtime, new admissions, and a new immutable release.

## Command sequence

The connector, recipe, engine, credentials, rights decision, release selection,
principal mapping, and timestamps are trusted authoring/operator inputs. They
never come from the model or its task.

Acquire and compile one authorized source observation:

```bash
datalox-author harvest \
  --request authoring-request.json \
  --out capture.json \
  --compiled-out program.json \
  --measurement-out measurement.json \
  --observed-at 2026-09-07T10:00:00Z \
  --rights-ref authorized-sandbox-agreement \
  --distribution restricted \
  --execute-sandbox-writes \
  --json
```

Run the exact compiled program against an immutable local release:

```bash
datalox-gate provider differential \
  --registry provider-releases \
  --reference provider@2026-09 \
  --profile reset-profile \
  --authority api.provider.example \
  --measurement measurement.json \
  --measurement-sha256 sha256:<canonical-measurement-digest> \
  --program program.json \
  --program-sha256 sha256:<exact-program-file-digest> \
  --principal-bindings principal-bindings.json \
  --observed-at 2026-09-07T10:05:00Z \
  --out differential-attestation.json
```

After a later authorized acquisition with the same connector, recipe, engine,
and seed, compare the provider observations:

```bash
datalox-gate provider drift compare \
  --report-id provider-program-2026-09-14 \
  --baseline-measurement baseline-measurement.json \
  --baseline-measurement-sha256 sha256:<digest> \
  --baseline-program baseline-program.json \
  --baseline-program-sha256 sha256:<digest> \
  --candidate-measurement candidate-measurement.json \
  --candidate-measurement-sha256 sha256:<digest> \
  --candidate-program candidate-program.json \
  --candidate-program-sha256 sha256:<digest> \
  --out drift-report.json
```

Pagination classifications require a digest-pinned scope file listing exact
program step IDs. The comparator never guesses pagination from paths, query
names, or response fields. Omit the candidate program only when the candidate
measurement is explicitly incomplete.

Derive and publish an assessment. An unchanged provider comparison requires the
candidate release-differential attestation; a changed provider comparison does
not blame the replica and therefore does not accept one as proof of currency.

```bash
datalox-gate provider drift assess \
  --assessment-id provider-program-2026-09-14 \
  --report drift-report.json \
  --report-sha256 sha256:<digest> \
  --release-manifest-sha256 sha256:<digest> \
  --profile reset-profile \
  --freshness-window-days 30 \
  --attestation differential-attestation.json \
  --attestation-sha256 sha256:<digest> \
  --out assessment.json

datalox-gate provider assessments create --root assessments
datalox-gate provider assessments publish \
  --root assessments \
  --assessment assessment.json
datalox-gate provider assessments status \
  --root assessments \
  --release-manifest-sha256 sha256:<digest> \
  --profile reset-profile \
  --program provider.program \
  --as-of 2026-09-30T00:00:00Z
```

## Assessment storage

Differential and drift assessments are append-only objects bound to a Provider
Release manifest digest, profile ID, and program ID. The registry stores their
content-addressed bytes and immutable chronological references. `latest` is
derived by validating and sorting the stored timestamps; no mutable pointer can
silently replace prior evidence.

Frozen releases remain runnable for reproducibility. A trusted operator may
require current grounding when selecting a release. The agent never selects
that policy.

## Initial executable checkpoint

OpenLMIS is the first checkpoint because the repository retains real write
programs and visible mismatches. `notification.update_contact_details` is the
first exact passing program against an immutable Provider Release, including
same-instance and fresh-instance reset equivalence. The exact capture and its
executable checkpoint remain restricted under the data-release policy. The
remaining programs continue to publish mismatch reports until a grounded
implementation correction or an explicit source-version distinction resolves
them. Comparison rules are never loosened merely to produce a pass.
