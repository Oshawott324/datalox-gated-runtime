import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import type { Dataset } from "@mastra/core/datasets";

import { mastra } from "./mastra/index.js";
import { worldStateScorer } from "./mastra/scorer.js";
import type {
  ExperimentGroundTruth,
  ExperimentInput,
  WorldRunOutput,
} from "./types.js";
import { dataRoot } from "./world-controller.js";
import { runWorldEpisode, type EpisodeExecutor } from "./world-run.js";

const DATASET_ID = "datalox-commerce-support-v0";
const DATASET_NAME = "Datalox commerce support v0";
const ITEM_INPUT: ExperimentInput = {
  prompt:
    "Retrieve the assigned task, investigate the linked evidence across services, and complete every permitted action. Do not stop at a recommendation.",
};
const ITEM_GROUND_TRUTH: ExperimentGroundTruth = { expectedReward: 1 };

export interface ExperimentOptions {
  name: string;
  executor: EpisodeExecutor;
  expectedScore?: number;
}

export async function runMastraExperiment(
  options: ExperimentOptions,
): Promise<void> {
  const dataset = await ensureDataset();
  const summary = await dataset.startExperiment<
    ExperimentInput,
    WorldRunOutput,
    ExperimentGroundTruth
  >({
    name: options.name,
    description:
      "Fresh Datalox world per item, Mastra MCP execution, hidden state scoring.",
    task: async ({ input }) => runWorldEpisode(options.executor, input),
    scorers: [worldStateScorer],
    maxConcurrency: 1,
    maxRetries: 0,
    itemTimeout: 300_000,
    metadata: {
      integration: "datalox-mastra-commerce-support-v0",
      reset: "fresh-container-per-item",
      verifier: "hidden-world-state",
    },
  });

  const experimentsDir = join(dataRoot(), "experiments");
  await mkdir(experimentsDir, { recursive: true });
  await writeFile(
    join(experimentsDir, `${summary.experimentId}.json`),
    `${JSON.stringify(summary, null, 2)}\n`,
    "utf8",
  );

  if (summary.status !== "completed" || summary.failedCount !== 0) {
    throw new Error(
      `Mastra experiment failed: status=${summary.status} failed=${summary.failedCount}`,
    );
  }
  const result = summary.results[0];
  const score = result?.scores.find(
    (candidate) => candidate.scorerId === "datalox-world-state",
  )?.score;
  if (typeof score !== "number") {
    throw new Error("Mastra experiment produced no Datalox world-state score");
  }
  if (options.expectedScore !== undefined && score !== options.expectedScore) {
    throw new Error(
      `expected score ${options.expectedScore}, received ${score}`,
    );
  }

  console.log(
    JSON.stringify(
      {
        experimentId: summary.experimentId,
        status: summary.status,
        score,
        reason: result?.scores[0]?.reason ?? null,
        runId:
          typeof result?.output === "object" &&
          result.output !== null &&
          "runId" in result.output
            ? result.output.runId
            : null,
      },
      null,
      2,
    ),
  );
}

async function ensureDataset(): Promise<Dataset> {
  const listed = await mastra.datasets.list({
    perPage: 100,
    filters: { name: DATASET_NAME },
  });
  const existing = listed.datasets.find((record) => record.name === DATASET_NAME);
  const dataset = existing
    ? await mastra.datasets.get({ id: existing.id })
    : await mastra.datasets.create({
        id: DATASET_ID,
        name: DATASET_NAME,
        description:
          "Stateful cross-service commerce-support tasks evaluated by hidden world state.",
        metadata: {
          worldId: "commerce_support_ops_v0",
          episodeId: "refund-duplicate-payment-clean",
        },
      });

  const listedItems = await dataset.listItems({ page: 0, perPage: 100 });
  if (Array.isArray(listedItems)) {
    throw new Error("expected paginated Mastra dataset items");
  }
  if (listedItems.items.length === 0) {
    await dataset.addItem({
      input: ITEM_INPUT,
      groundTruth: ITEM_GROUND_TRUTH,
      metadata: { episodeId: "refund-duplicate-payment-clean" },
    });
  } else if (listedItems.items.length !== 1) {
    throw new Error("the example dataset must contain exactly one item");
  }
  return dataset;
}
