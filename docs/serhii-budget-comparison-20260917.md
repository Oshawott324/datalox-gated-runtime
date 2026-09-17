# A feasible call limit produced no observed regression

September 17, 2026. Follow-up to the
[repeated-run baseline](serhii-noise-floor-20260912.md) and the experiment with
Serhii Nazarov in [Issue #6](https://github.com/Oshawott324/datalox-gated-runtime/issues/6).

All 90 real-agent tasks passed. The 12-call limit never rejected a request.
It was feasible, but it did not constrain the agent in this cohort. This result
does not demonstrate regression-detection sensitivity.

| Arm | Clean passes | Hostile passes | Budget stops |
| --- | ---: | ---: | ---: |
| Baseline | 15/15 | 15/15 | 0 |
| 12-provider-call limit | 15/15 | 15/15 | 0 |
| Reporting-only label | 15/15 | 15/15 | 0 |

Each arm/profile/policy-seed cell contains five repetitions. The call limit
was chosen before collection using the earlier baseline: all 60 earlier runs
finished in 10–12 provider calls. It remains 12 after this null result.

## Inspect the evidence without inference

The [experiment release](https://github.com/Oshawott324/datalox-gated-runtime/releases/tag/serhii-budget-comparison-20260917)
contains all 90 reviewed provider/tool traces, their checksums, and the exact
public source snapshot used for the collection's code bindings. With `uv`
installed, run in a new directory:

```bash
curl --fail --location --remote-name \
  https://github.com/Oshawott324/datalox-gated-runtime/releases/download/serhii-budget-comparison-20260917/serhii-budget-comparison-20260917-evidence.tar.gz
curl --fail --location --remote-name \
  https://github.com/Oshawott324/datalox-gated-runtime/releases/download/serhii-budget-comparison-20260917/serhii-budget-comparison-20260917-source.tar.gz
curl --fail --location --remote-name \
  https://github.com/Oshawott324/datalox-gated-runtime/releases/download/serhii-budget-comparison-20260917/SHA256SUMS
shasum -a 256 -c SHA256SUMS
tar -xzf serhii-budget-comparison-20260917-evidence.tar.gz
mkdir source
tar -xzf serhii-budget-comparison-20260917-source.tar.gz -C source
uv run --frozen --project source/integrations/verifiers_dirty_integration \
  datalox-dirty-public-evidence --source evidence-reviewed-20260917
```

Expected: `passed: true`, `runs: 90`, summary identity
`sha256:4184ade85cf7fda57e4a48d6001c3427ca7739d3588afedb1a4dba258fb7209c`.
Installation downloads dependencies; evidence verification performs no model
inference or live provider calls and needs no API key.

The original manifest retains its development revision plus per-file hashes
of then-uncommitted code. The source archive matches all 168 file bindings.
The later publication branch/tag contains the focused runner change and this
report; use the archive for the exact collected snapshot, including its frozen
dependency declarations. Earlier evidence remains unchanged.

## What varied and what stayed fixed

All three arms have the same per-cell outcomes:

| Profile / policy seed | Calls per run | Existing discipline score |
| --- | ---: | ---: |
| Clean / 1, 7, 23 | 10 | 1 |
| Hostile / 1 | 10 | 1 |
| Hostile / 7 | 11 | 10/11 |
| Hostile / 23 | 12 | 10/12 |

Hostile seed 7 produced two distinct provider traces in baseline, three under
the call limit, and two under the reporting label. Seed 23 produced three per
arm. Clean and hostile seed 1 each produced one per cell.

For example, baseline seed 7 sometimes read product offsets
`0,10,20,20,30,40,50` and sometimes `0,10,20,30,40,30,50`. Both paths finished
correctly in 11 total provider calls. Five interventions were applied, but
four or five changed the delivered observation, depending on the path.

The reporting label was outside every agent-visible input. These small
path-frequency differences do not establish a label effect. Trace variation
and effective fault exposure remain diagnostics; neither alone is a release
failure. The preserved discipline formula also does not establish that extra
recovery calls were avoidable.

## Collection and acceptance

- GPT-5.6 Sol, medium reasoning, native Verifiers 0.3.1 Responses loop;
  temperature omitted and model RNG seed unset.
- Same task, tools, reset state, policies and scoring as the baseline. No new
  recovery hints or evaluation truth in the agent input. The model selected
  actions, arguments and stopping points; scripted clients were tests only.
- Three arms, clean/hostile profiles, policy seeds 1/7/23, five repetitions;
  counterbalanced sequential order, fresh state/process, zero client retries.
- The limit counts dispatched provider calls, including writes and fault
  results. Call 12 is delivered normally; call 13 would stop before dispatch
  through a native harness stop, with no fabricated provider response.
- 90/90 collected and audited, 945 provider calls, zero collection errors,
  zero budget stops. Every native termination was `no_tools_called`.
- Accounted model-token cost: $5.9956378. A separate pre-funding attempt
  produced a credit error before generation; its retained $0.40 safety hold
  keeps combined accounting below the approved $7. The hold is not a confirmed
  billed charge. No failed slot was silently replaced.
- Re-analysis reproduced all three private analysis files byte-for-byte. The
  180-pair model-free calibration remained unchanged. Controller boundary tests
  exercise rejected call 13 separately from these model-selected runs.
- Public projection verification passed for all 90 rows, including a check
  using the archived source with inference credentials unset. Source and
  evidence secret scans passed.

## Scope

This is a downstream reference experiment: the consumer owns the task,
verifier, reward and harness controls. Datalox supplies provider behavior and
separate intervention evidence.

The evidence contains synthetic catalog/cart state and an `example.test`
contact, using the bounded G2 Medusa 2.16.0 reference slice. These are local
executions, not new live-provider captures. Read interventions remain authored.
The projection preserves tool calls/results and controller evidence while
excluding assistant prose, opaque reasoning, inference receipts and machine
paths. It does not independently expose the full private native/model audit.
Evidence and ground truth are evaluator-only artifacts, never agent input.

Five repetitions per cell, one task, one tenant and one model configuration
support a descriptive result, not statistical equivalence or a release
threshold. The cap reached the successful 12-call boundary without blocking
any run. A future sensitivity test needs a separately declared, still-feasible
case that actually exercises the intended failure boundary.
