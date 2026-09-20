# Eleven-call follow-up: a specific prediction, tested separately

The September 17 comparison used a 12-call cap. All 90 tasks passed; no run
requested call 13. Serhii proposed 11 because every earlier `hostile/23` run
updated the cart on call 11 and confirmed it with `get_cart` on call 12.

This follow-up keeps those results intact. It changes the controller's cap,
keeps the task unchanged, and tests a prediction made before collection.
It is a downstream experiment, not a new Datalox task or reward contract.

## Frozen prediction

- Uncapped runs should continue to pass.
- Under the 11-call cap, `hostile/23` should complete its writes and then request
  a confirmation that the controller blocks before dispatch. The existing
  verifier should name `confirmation_read_matches` as the failed check.
- The other five profile/seed settings should pass within 10–11 calls.
- Final provider state should match the completed task even where confirmation
  is missing. Check state separately: the verifier returns after its first
  failing check, so later checks are not evaluated in that case.

These are predictions, not collection filters. Changed trajectories, a null
result, other failures, incomplete slots, and unexpected outcomes remain in
the report. No repeated slot or replacement run is allowed.

## Two kinds of evidence

First re-execute the 60 reviewed baseline action sequences locally, both
uncapped and capped. An uncapped replay must reproduce the original delivered
observations, final provider state and scores. The capped replay uses fresh
state and the actual controller; it does not truncate and regrade saved JSON.
This recorded-action counterfactual makes no new model-performance claim.

Then collect 36 new model-selected runs: baseline versus 11-call cap, clean and
hostile, policy seeds 1/7/23, three repetitions per cell. Sequential arm order
is counterbalanced: nine blocks in each order, 2/1 within each cell.
The smaller sample is a targeted follow-up, not a precise population estimate.

GPT-5.6 Sol medium, native Verifiers 0.3.1 Responses loop, temperature omitted,
model seed unset, parallel tool calls disabled. Keep the previous prompt, tools,
tenant state, provider release, intervention policies and component scores.
The cap and expected failure are controller/evaluation information; neither
appears in the agent's instructions or tools. Model actions remain unscripted.

Provider calls through 11 execute normally. A valid request for call 12 causes
the native harness to stop before dispatch, without a fabricated provider
response, extra intervention, retry, or extra inference. Calls include writes
and delivered read-fault responses. Final answers require no provider call.

## Spending and reporting

- API model-token cap: $3 total, $0.40 reservation per rollout, concurrency one.
  Stop with an incomplete cohort if the next reservation cannot fit.
- Zero client/evaluator retries. Preserve any uncertain-charge reservation.
- Report each cell's completion, correctness, named failed checks, calls,
  rejected request, final state and discipline score. Keep correctness separate
  from the existing discipline score; fewer calls can improve that score even
  when confirmation is missing.
- Compare expected localization against all observed cells. Trace differences
  remain diagnostic. This establishes no automatic release threshold or
  broad regression-detection sensitivity.
- Native traces and model responses remain private pending release review.

## Commands

Run from the repository's Verifiers integration environment. Extract the
previous reviewed baseline archive to `baseline-evidence/` first.

```bash
python -m datalox_dirty_integration.repeat_replay \
  --source baseline-evidence --limit 11 --output counterfactual.json

python -m datalox_dirty_integration.repeats prepare \
  --experiment-version v3 --experiment-id serhii-budget11-20260918 \
  --max-total-cost-usd 3 --per-rollout-reservation-usd 0.4 \
  --output experiment.json

# Requires a funded OPENAI_API_KEY; begins paid inference.
python -m datalox_dirty_integration.repeats run \
  --experiment experiment.json --output collection --spend-approved

python -m datalox_dirty_integration.repeats analyze \
  --source collection --output analysis
```

V1 and V2 manifests retain their original schedules. V3 admits exactly this
36-slot schedule. Each collection binds the actual source files in addition
to the checked-out revision; uncommitted source must be preserved with the
evidence before publication.
