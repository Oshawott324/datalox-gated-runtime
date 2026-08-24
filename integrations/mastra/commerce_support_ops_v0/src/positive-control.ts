import { runMastraExperiment } from "./experiment.js";
import { positiveControl } from "./policies.js";

await runMastraExperiment({
  name: "positive integration control",
  executor: positiveControl,
  expectedScore: 1,
});
