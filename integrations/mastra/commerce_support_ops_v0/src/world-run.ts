import type { Tool } from "@mastra/core/tools";

import { createMcpClient, selectAgentTools, type MCPToolMap } from "./mcp.js";
import type {
  ExecutorResult,
  ExperimentInput,
  WorldRunOutput,
} from "./types.js";
import { WorldController } from "./world-controller.js";

export interface EpisodeContext {
  rawTools: MCPToolMap;
  agentTools: Record<string, Tool>;
}

export type EpisodeExecutor = (
  context: EpisodeContext,
  input: ExperimentInput,
) => Promise<ExecutorResult>;

export async function runWorldEpisode(
  executor: EpisodeExecutor,
  input: ExperimentInput,
): Promise<WorldRunOutput> {
  const controller = await WorldController.start();
  const client = createMcpClient(controller.baseUrl);
  let executorError: unknown;
  let execution: ExecutorResult | undefined;

  try {
    try {
      const rawTools = await client.listTools();
      execution = await executor({
        rawTools,
        agentTools: selectAgentTools(rawTools),
      }, input);
    } catch (error) {
      executorError = error;
    } finally {
      await client.disconnect();
    }

    const verdict = await controller.finalize();
    if (executorError !== undefined) {
      throw executorError;
    }
    if (!execution) {
      throw new Error("episode executor returned no result");
    }
    const result: WorldRunOutput = {
      ...execution,
      runId: controller.runId,
      verdict,
    };
    await controller.writeRunResult(result);
    return result;
  } finally {
    await controller.stop();
  }
}
