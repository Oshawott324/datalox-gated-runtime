import { runMastraExperiment } from "./experiment.js";
import { liveAgentPolicy } from "./policies.js";

await runMastraExperiment({
  name: `Mastra agent: ${process.env.MASTRA_MODEL ?? "openai/gpt-5-mini"}`,
  executor: liveAgentPolicy(),
});
