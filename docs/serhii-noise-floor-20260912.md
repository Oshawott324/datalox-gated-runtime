# Repeated agent runs: stable scores, different API-call paths

September 12, 2026. A bounded experiment developed with Serhii Nazarov around
[Issue #6](https://github.com/Oshawott324/datalox-gated-runtime/issues/6).

All 60 model-driven tasks passed. Clean runs made identical provider requests
and received identical observations. Two hostile seeds each produced three
different provider trajectories, while their task scores, total call counts,
and request-discipline scores stayed constant within the seed.

| Profile / seed | Runs | Task passes | Provider calls per run | Discipline | Distinct provider traces |
| --- | ---: | ---: | ---: | ---: | ---: |
| Clean / all three scheduling blocks | 30 | 30 | 10 | 1 | 1 |
| Hostile / 1 | 10 | 10 | 10 | 1 | 1 |
| Hostile / 7 | 10 | 10 | 11 | 10/11 | 3 |
| Hostile / 23 | 10 | 10 | 12 | 10/12 | 3 |

The lesson for a release check is specific: a score-only baseline would miss
the action-path variation observed here. This experiment does not establish
that the variation causes task failures or materially changes a release threshold.

## Inspect all 60 runs without a model or API key

The [experiment release](https://github.com/Oshawott324/datalox-gated-runtime/releases/tag/serhii-noise-floor-20260912)
contains the reviewed evidence archive, checksums, exact public source snapshot,
runtime dependency SBOM, and a publication provenance record. Use that source
snapshot, or check out the release tag in the public repository.

From the repository root, with `uv` installed:

```bash
curl --fail --location --remote-name \
  https://github.com/Oshawott324/datalox-gated-runtime/releases/download/serhii-noise-floor-20260912/serhii-noise-floor-20260912.tar.gz
curl --fail --location --remote-name \
  https://github.com/Oshawott324/datalox-gated-runtime/releases/download/serhii-noise-floor-20260912/EVIDENCE_SHA256SUMS
shasum -a 256 -c EVIDENCE_SHA256SUMS
tar -xzf serhii-noise-floor-20260912.tar.gz
uv run --frozen --project integrations/verifiers_dirty_integration \
  datalox-dirty-public-evidence --source serhii-noise-floor-20260912
```

Expected: `passed: true`, `runs: 60`, and summary identity
`sha256:3849cfb1817645badb6f522b07539cfa32358e6d9ac2132a5f02fa44e72f94fe`.
Installation downloads Python dependencies. The evidence check itself performs
no inference or provider access.

`summary.json` groups the runs and identifies their paths. `rollouts.jsonl`
contains every scheduled pilot run, including ordered tool calls/results, base
provider receipts and final state, intervention decisions, delivered observations,
and separate verifier components. No successful subset was selected. The two
preflight smoke runs are excluded from the pilot.

The checker verifies the exact file inventory and digests, complete ordered
schedule, original controller-artifact byte commitments, frozen provider/policy
bindings, tool-to-observation joins, intervention effects, recomputed task and
discipline components, and the provider-only summary. Its adversarial tests
cover omitted/reordered runs, altered observations, tool arguments and scores,
extra model prose, changed summaries, unreviewed files and symlinks.

## One revealing pair

Compare `r001-s002-hostile` and `r002-s002-hostile`, both policy seed `7`.
Their first three requests and observations match. At the fourth product read:

| | First run | Second run |
| --- | --- | --- |
| Requested offset | 20, retry | 30, advance |
| Base response offset | 20 | 30 |
| Policy decision | Repeat raw page from request 3 | Same |
| Delivered offset | 20 | 20 |
| `observation_changed` | false | true |

The policy references the raw base page, not the already modified observation.
The first request divergence is position 4; the first delivered-observation
divergence is position 5. Both runs finish correctly with 11 provider calls.

Seed 7's three read-offset paths occur 7, 2 and 1 times; seed 23's occur 8, 1
and 1 times. In seven seed-7 runs, five applied interventions change four
observations; in the other three, they change five. This gives Serhii's
`observation_changed` distinction a concrete use: an identical intervention
decision can have a different effective impact depending on the request.

## Configuration and collection

- Model: `gpt-5.6-sol`, medium reasoning, OpenAI Responses API, default tier,
  `store=false`. Temperature omitted; model RNG seed unset. This is not a
  temperature-zero baseline.
- Harness: Verifiers `0.3.1`, native Responses client and native
  `Environment.evaluate`. The model selects all tools, arguments and stopping
  points; the reference client supplies no rollout actions.
- One fixed Medusa cart task and reset state. Clean/hostile profiles, policy
  seeds `1`, `7`, `23`, ten repetitions per profile/seed. Clean seed labels are
  scheduling blocks, not three different tasks.
- Separate processes and fresh provider state, sequential execution, no SDK
  or evaluator retries, parallel tool calls disabled. Thirty-turn limit;
  4,096 output tokens per response; 120-second request and 900-second rollout
  timeouts. Only product-list calls advance the intervention index.
- All 60 slots completed and passed the private native/controller audit.
  Zero collection errors, replacements, quota exposure, timeouts or truncation.
- The pilot made 690 model requests with accounted model-token cost $3.994867.
  Including the separate smoke and successful parameter preflight: $4.132510
  of the authorized $10. These are controller-accounted costs, not a published
  billing-receipt audit. New inference needs separately approved spending.

The [runner instructions](../integrations/verifiers_dirty_integration/README.md#measure-repeated-run-variation)
cover preparing a new frozen manifest, collection and full private analysis.
The original `experiment.json` stays unchanged. It references the development
revision plus individual hashes of the then-uncommitted runner files; that
revision alone never contained the runner. The publication tag is a later
reviewed implementation snapshot, including #10 and evidence-inspection tooling.
Hashes, rather than an invented historical commit, identify the collected code.

## Release and interpretation boundary

The public bundle is an explicitly derived **provider/tool evidence view**.
It preserves the original controller values and serialized tool calls/results,
but excludes assistant prose, opaque reasoning, raw inference responses and
receipts, and machine-local paths. Original native-result and index hashes are
retained as commitments, not proof that a third party can inspect withheld bytes.
Full native continuity, inference usage and hosted-model identity cannot be
independently re-audited from this projection. The full private analysis was
repeated before publication and reproduced its original bytes exactly.

All published data use the self-authored catalog, local generated cart/line
identifiers, and an `example.test` contact. There are no live-provider response
payloads or real tenant records. The base runtime is the already released,
bounded Medusa 2.16.0 slice backed by G2 reference facts; these model rollouts
are local executions, not new provider captures. The read-fault policies remain
authored interventions. Each published file has an explicit rights, sensitivity,
grounding and content-hash entry in `PUBLIC_EVIDENCE_MANIFEST.json`.

All evidence and oracle data are controller-only artifacts. A researcher can
inspect them after a rollout; they must stay outside agent prompts and tools.

This is one task, one tenant state, one model configuration and three hostile
schedules. Within-seed score/count sample variation happened to be zero.
The 270 pairwise comparisons reuse the same 60 runs. No quota or task-failure
boundary was tested by the model cohort. Clean versus hostile changes quota
and fault exposure together; it does not isolate the causal effect of index
coupling. The hosted-model backend fingerprint was unavailable.

The deterministic V1 gate remains separate: all 180 pairs reproduce the existing
calibration report exactly. Serhii's
[#10 verifier regressions](https://github.com/Oshawott324/datalox-gated-runtime/pull/10)
are merged with his authorship preserved; their 10 tests also pass. Thanks to
Serhii for the observation-effect distinction, additive verifier cases, and the
proposal to measure repeated-run variation before introducing regressions.
