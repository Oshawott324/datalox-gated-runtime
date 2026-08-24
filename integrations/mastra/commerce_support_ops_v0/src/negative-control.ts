import { runMastraExperiment } from "./experiment.js";
import { negativeControl } from "./policies.js";

await runMastraExperiment({
  name: "forbidden action negative control",
  executor: negativeControl,
  expectedScore: 0,
});
