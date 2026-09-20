# Eleven calls blocked confirmation in exactly the predicted setting

September 20, 2026. Follow-up with Serhii Nazarov in
[Issue #6](https://github.com/Oshawott324/datalox-gated-runtime/issues/6), using
the [frozen eleven-call protocol](serhii-budget11-protocol.md).

All 18 uncapped runs passed. With the 11-call limit, 15 passed and three
failed: the three `hostile/23` repetitions. Each completed its cart update on
call 11, then requested `get_cart` as call 12. The controller stopped that
request before dispatch. The verifier named `confirmation_read_matches`.

| Profile / policy seed | Uncapped passes | Capped passes | Calls, uncapped → capped |
| --- | ---: | ---: | ---: |
| Clean / 1 | 3/3 | 3/3 | 10 → 10 |
| Clean / 7 | 3/3 | 3/3 | 10 → 10 |
| Clean / 23 | 3/3 | 3/3 | 10 → 10 |
| Hostile / 1 | 3/3 | 3/3 | 10 → 10 |
| Hostile / 7 | 3/3 | 3/3 | 11 → 11 |
| Hostile / 23 | 3/3 | 0/3 | 12 → 11 |

All 36 final provider business states were equal: one cart, the lowest-priced
variant, quantity three, unit price 1000, total 3000, and the expected synthetic
customer email. We checked that state separately because the verifier stops
at its first failed check. Event histories differ when confirmation is absent.

This comparison detected and localized the predicted missing confirmation.
It does not establish a general release threshold or measure how often a
different agent would recover within the cap.

## Inspect all 36 runs without inference

The [experiment release](https://github.com/Oshawott324/datalox-gated-runtime/releases/tag/serhii-budget11-20260920)
contains reviewed tool/provider traces, the exact collected source snapshot,
the earlier interrupted attempt, and model-free checks. With `uv` installed,
run in a new directory:

```bash
set -e
base=https://github.com/Oshawott324/datalox-gated-runtime/releases/download/serhii-budget11-20260920
for asset in serhii-budget11-20260920-evidence.tar.gz \
  serhii-budget11-20260920-source.tar.gz \
  serhii-budget11-20260920-supplement.tar.gz \
  PUBLIC_SOURCE_MANIFEST.json datalox-runtime-sbom.cdx.json \
  BUILD_PROVENANCE.json SHA256SUMS; do
  curl --fail --location --remote-name "$base/$asset"
done
shasum -a 256 -c SHA256SUMS
tar -xzf serhii-budget11-20260920-evidence.tar.gz
mkdir source
tar -xzf serhii-budget11-20260920-source.tar.gz -C source
uv run --frozen --project source/integrations/verifiers_dirty_integration \
  datalox-dirty-public-evidence --source evidence-reviewed-20260920
```

Expected: `passed: true`, `runs: 36`, summary identity
`sha256:e330a414436bc987ed6e6b04b93008660b83611fbc3b6fc156ae5eb59b80fc52`.
Installation downloads dependencies; verification needs no inference key and
makes no model or live-provider calls.

The source archive matches all 169 source-file bindings in the collection
manifest, including the frozen dependency declarations. That manifest retains
the development revision and hashes of then-uncommitted code. The later
publication branch/tag contains the focused change and this report; use the
archive for the exact collected snapshot.

## What changed, and what the scores mean

Only the controller's call cap changed between arms. GPT-5.6 Sol medium ran
through native Verifiers 0.3.1, with temperature omitted, model seed unset,
and parallel tool calls disabled. The task, tools, provider release, initial
state, read interventions and scoring were unchanged. The agent chose its
actions; the cap and expected failure stayed outside its inputs.

The existing discipline score is based on calls used, independently of task
correctness. For `hostile/23`, it increased from 10/12 to 10/11 while correctness
fell from one to zero. Fewer calls alone therefore do not mean a better result.
Both components remain visible; we did not change the formula after observing
the outcome.

For hostile seed 7, all six runs received five applied interventions. Four
runs had five changed observations and two had four. Every run still passed
in 11 calls. Effective fault exposure remains a diagnostic, consistent with
the earlier baseline analysis.

## Collection, cost and checks

- 36/36 scheduled runs collected and audited; three repetitions for each
  arm/profile/seed, counterbalanced sequential arm order, fresh state/process.
- 375 dispatched provider calls; 33 native `no_tools_called` stops and three
  `harness_call_budget_exhausted` stops. No fabricated provider response for
  a rejected call, no collection errors, retries or replacement slots.
- Accounted model-token cost: **$2.402447**, within the newly approved $3 cap.
  411 model responses used 1,990,317 input tokens (including 1,713,375 cache
  reads and 253,209 cache writes) and 17,806 output tokens (including 3,945
  reasoning tokens). No unsettled reservation remains in this batch.
- Re-analysis reproduced all three native analysis files byte-for-byte.
  Every public row passed the retained tool/provider evidence checks, and
  the source snapshot matched every bound file.
- The deterministic 180-pair calibration retained its semantic digest:
  `sha256:862fe06826f65ab1794ff8b49f297053532c622c098bf29be636548e4cff6e89`.
- Fresh-install integration tests, public-source tests, offline demo, package
  builds and secret scans passed. The release records the actual checks and
  runtime dependency audit in publisher-generated provenance, not a signed
  CI attestation.

The [September 18 attempt](serhii-budget11-20260918.md) remains separate. Three
runs completed before an OpenAI 503 stopped the fourth at its first model
request; 32 slots were unstarted. Its $0.1816836 settled cost and $0.40
conservative reservation are retained. That reservation is not a confirmed
billed charge. None of those runs was substituted into this cohort.

## Recorded-action check and public evidence limits

The supplemental archive includes a local re-execution of all 60 earlier
baseline action sequences through fresh provider state. All 60 uncapped
replays passed; under the cap, the ten `hostile/23` sequences failed only the
confirmation check and the other 50 passed. Final business state stayed
correct. This uses recorded actions, not new model rollouts.

Fresh runtimes assign fresh audit identities and creation times. Those change
the full rejection-receipt digest between independent replays; delivered
observations, provider state and scores are checked separately. The report
does not claim byte-identical full receipts across fresh runtimes.

Public traces retain original serialized tool calls/results, provider state,
interventions, component scores and controller receipts. Raw model prose,
opaque reasoning, inference receipts and private machine paths remain
withheld. Native-file hashes are commitments to those private records, not
an independent public native audit. The interrupted-attempt supplement checks
its three completed projections; its error summary is publisher-reported.

This is a bounded downstream Medusa reference experiment with a synthetic
tenant and separately authored read interventions, not a new live-provider
capture. Datalox supplies provider behavior; consumers own tasks, agents,
verifiers, rewards and training decisions.
