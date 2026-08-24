import { mkdirSync } from "node:fs";
import { join } from "node:path";

import { Mastra } from "@mastra/core";
import { LibSQLStore } from "@mastra/libsql";

import { dataRoot } from "../world-controller.js";
import { worldStateScorer } from "./scorer.js";

mkdirSync(dataRoot(), { recursive: true });

export const mastra = new Mastra({
  storage: new LibSQLStore({
    id: "datalox-mastra-commerce-support",
    url: `file:${join(dataRoot(), "mastra.db")}`,
  }),
  scorers: {
    worldStateScorer,
  },
});
