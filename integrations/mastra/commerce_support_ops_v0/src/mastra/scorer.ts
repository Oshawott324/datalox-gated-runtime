import { createScorer } from "@mastra/core/evals";

import type { ExperimentInput, WorldRunOutput } from "../types.js";

export const worldStateScorer = createScorer<ExperimentInput, WorldRunOutput>({
  id: "datalox-world-state",
  name: "Datalox hidden world-state verifier",
  description:
    "Scores the package-bound hidden state verdict produced after the agent exits.",
})
  .generateScore(({ run }) =>
    run.output.agentError === null ? run.output.verdict.audit.reward : 0,
  )
  .generateReason(({ run, score }) => {
    if (run.output.agentError) {
      return `Agent execution failed: ${run.output.agentError.message}`;
    }
    if (score === 1) {
      return "All hidden state and process invariants passed.";
    }
    const codes = run.output.verdict.audit.failure_codes;
    return codes.length > 0
      ? `Hidden verifier failed: ${codes.join(", ")}`
      : "Hidden verifier returned a failing reward.";
  });
