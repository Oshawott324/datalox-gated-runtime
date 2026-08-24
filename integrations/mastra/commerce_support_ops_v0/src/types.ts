export interface SerializableError {
  name: string;
  message: string;
}

export interface WorldVerdict {
  schema_version: string;
  package_content_sha256: string;
  source_manifest_sha256: string;
  world_id: string;
  bundle_version: string;
  episode_id: string;
  task_id: string;
  audit: {
    passed: boolean;
    reward: number;
    reward_source: string;
    failure_codes: string[];
    sha256: string;
  };
  run_export_sha256: string;
}

export interface ExecutorResult {
  responseText: string | null;
  model: string;
  agentError: SerializableError | null;
  modelSteps: number | null;
  toolCalls: number;
}

export interface WorldRunOutput extends ExecutorResult {
  runId: string;
  verdict: WorldVerdict;
}

export interface ExperimentInput {
  prompt: string;
}

export interface ExperimentGroundTruth {
  expectedReward: number;
}

export function serializeError(error: unknown): SerializableError {
  if (error instanceof Error) {
    return { name: error.name, message: error.message };
  }
  return { name: "Error", message: String(error) };
}
