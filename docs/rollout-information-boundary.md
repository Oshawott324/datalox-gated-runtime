# Rollout Information Boundary

Every rollout integration in this repository keeps three information planes
separate. This is an execution invariant, not a prompting convention.

## 1. Task plane

The agent may receive the task objective and the scientific or operational
constraints that are intentionally available to the worker before it acts.
Examples include the requested outcome, safety limits, permitted tools, and a
known experimental protocol.

An initial provider response, an anomaly that the environment has not yet
produced, an answer key, an expected trajectory, and hidden verifier criteria
do not belong in this plane. A fact that is genuinely known to the worker at
task start may be stated here; its classification follows the disclosure
contract of the real workflow.

## 2. Observation plane

The environment reveals observations causally during interaction. A provider
response follows the agent action that invoked that provider operation. A
webhook, delayed job result, timeout, permission error, instrument anomaly, or
other environment event appears when its declared behavior makes it observable.

Provider observations travel through the agent loop's normal tool-result or
environment-observation channel. Datalox examples never prefetch provider state
and append it to the initial task prompt. Observations contain the behavior the
agent can actually observe, without oracle annotations or expected values.

## 3. Evaluation plane

Evaluation ground truth is available only to trusted task generation, oracle,
and verifier code. It includes expected final state, accepted equivalence
classes, hidden object identities, answer keys, scoring predicates, and other
facts used to construct or evaluate an episode.

This plane may consume controller-only rollout exports after execution. It is
absent from model prompts, tool schemas, provider responses, task-container
inputs, and model-readable logs. Keeping a hidden value in the same source
package is acceptable only when compilation and runtime access keep it behind
the trusted evaluation boundary.

## Required information flow

```text
trusted task generator ── task objective + visible constraints ──> agent
                                                                  │
                                                                  │ action
                                                                  ▼
                                                        provider/environment
                                                                  │
                                                                  │ observation
                                                                  ▼
                                                                agent

trusted oracle/verifier <── controller-only evidence + evaluation ground truth
```

The causal rollout sequence is:

```text
task → agent action → environment observation → later agent action → ...
```

There is no evaluation-to-agent edge.

## Repository enforcement

- [`product-contract.json`](../product-contract.json) records the invariant in
  the public product contract.
- Every checked rollout adapter declares its carriers in a
  `rollout-information-boundary.json` manifest validated by
  [`rollout-information-boundary-v1.schema.json`](../schemas/rollout-information-boundary-v1.schema.json).
- The rollout pool accepts only lease identity, an operator-fixed task image,
  and a consumer-authored argv command. Its strict wire contract defines no
  task, prompt, observation, oracle, or evaluation field.
- Provider runtime compilation removes world-owned `task`, `hidden`, and
  `expected` fields from the provider seed.
- The veRL example contains only the consumer's task plane in its dataset row;
  provider observations enter through model-selected function tools.
- The Slime example exposes a provider tool callback for the consumer's
  existing agent loop. Calling the callback produces an observation; importing
  or wrapping the adapter produces none.
- Regression tests validate the manifests and inspect the checked examples for
  forbidden cross-plane access.

Structural enforcement cannot determine whether arbitrary consumer prose
secretly contains an answer key. Consumers remain responsible for classifying
their own task content. Datalox makes the correct carriers explicit and keeps
its runtime and examples from creating a cross-plane path.
