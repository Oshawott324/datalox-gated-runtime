# Eleven-call follow-up: replay confirmed; live collection interrupted

September 18, 2026. Follow-up to the
[12-call comparison](serhii-budget-comparison-20260917.md), using the separately
frozen [11-call protocol](serhii-budget11-protocol.md).

Re-executing the 60 saved baseline action sequences confirmed the specific
prediction: the 11-call cap blocked the final confirmation in `hostile/23`,
while the other five settings still passed. The new live comparison remains
incomplete: OpenAI returned HTTP 503 on the fourth rollout. No retry or
replacement was made.

## Recorded-action replay, without inference

Each original sequence was run twice against fresh local state: uncapped,
then with the actual 11-call controller. Every uncapped replay reproduced
the original observations, final provider export and component scores.

| Profile / seed | Uncapped passes | Eleven-call passes | Failed check under cap |
| --- | ---: | ---: | --- |
| Clean / 1 | 10/10 | 10/10 | — |
| Clean / 7 | 10/10 | 10/10 | — |
| Clean / 23 | 10/10 | 10/10 | — |
| Hostile / 1 | 10/10 | 10/10 | — |
| Hostile / 7 | 10/10 | 10/10 | — |
| Hostile / 23 | 10/10 | 0/10 | `confirmation_read_matches` |

In each affected replay, the quantity update completed on call 11, and the
controller rejected the requested `get_cart` at call 12 before dispatch.
Cart/catalog data matched the original successful run in all 60 cases.
The complete provider export includes event history, so it correctly differs
in the ten cases where the confirmation read was omitted. Both comparisons
are reported separately.

These are saved actions re-executed locally, not new model decisions. They
verify the controller and named-check prediction for those recorded paths;
they do not establish what a fresh model rollout will do.

## New model-selected runs

The manifest scheduled 36 GPT-5.6 Sol medium runs: baseline versus capped,
clean/hostile, seeds 1/7/23, three repetitions per cell. All 13 non-file
scientific/dependency bindings matched the preceding experiment. The source
snapshot matches all 169 code/dependency file bindings.

- Completed and audited: 3; all passed in 10 provider calls.
- Completed settings: clean/1 baseline, clean/1 capped, hostile/1 capped.
- Collection error: hostile/1 baseline, first model request; HTTP 503,
  `server_is_overloaded`, before any provider call.
- Unstarted: 32. The `hostile/23` setting was not reached.
- Settled model-token cost: $0.1816836. The collector retains a conservative
  $0.40 reservation for the failed rollout; that hold is not a billed charge.
  Settled cost plus held reservation is $0.5816836, within the $3 cap.

The complete analysis retains all 36 scheduled entries, including the error
and unstarted entries. It marks the cohort incomplete. Re-analysis reproduced
the summary JSON, readable report and rollout JSONL byte-for-byte.

This collection supplies no live regression-localization result. Finish that
question with a newly authorized, separately identified collection after the
service recovers; preserve this attempt and its spending record.

## Implementation review

- 368 repeat-runner tests passed with the pinned Verifiers dependency,
  including cap boundaries for reads and writes, native stopping, evidence
  tamper detection, fixed V3 scheduling, and public projection.
- The existing 180-pair calibration passed and exactly matched its prior
  report, digest
  `sha256:862fe06826f65ab1794ff8b49f297053532c622c098bf29be636548e4cff6e89`.
- The prior public 90-run evidence still verifies with its original summary
  digest. V1/V2 schedules and previous artifacts remain unchanged.
- The frozen public source passed 1,556 tests with 110 optional tests skipped,
  lint/format checks, the offline demo, and source/wheel builds. Native
  Verifiers tests were run separately above.
- Public release classification checks passed. No new evidence was published
  and no partner message was sent.

The frozen experiment identity is
`sha256:324e0add496917cb96254dbabd08de7a9e10ae69cccc3c8ccedc988165b33f0a`.
The incomplete analysis file digest is
`sha256:4a7b1f6c9be20c032910a2c4de64308821d2fd8a77d157000b8f8bff6ee234d9`.
Local evidence is retained in the `serhii-budget11-20260918` experiment folder:
`recorded-action-counterfactual-reviewed.json`, `experiment.json`,
`collection/`, `analysis/`, `analysis-recheck/`, `calibration-180-pairs.json`,
and `source-public-frozen/`.
