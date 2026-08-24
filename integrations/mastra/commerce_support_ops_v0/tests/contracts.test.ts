import assert from "node:assert/strict";
import test from "node:test";

import { selectedToolAliases } from "../src/mcp.js";
import { worldStateScorer } from "../src/mastra/scorer.js";
import type { WorldRunOutput } from "../src/types.js";
import { parsePublishedPort } from "../src/world-controller.js";

function output(reward: number): WorldRunOutput {
  return {
    runId: "run-test",
    responseText: "done",
    model: "test",
    agentError: null,
    modelSteps: null,
    toolCalls: 1,
    verdict: {
      schema_version: "datalox_world_package_verdict_v1",
      package_content_sha256: "sha256:package",
      source_manifest_sha256: "sha256:source",
      world_id: "commerce_support_ops_v0",
      bundle_version: "1.0.0",
      episode_id: "refund-duplicate-payment-clean",
      task_id: "commerce-support-ops-00",
      audit: {
        passed: reward === 1,
        reward,
        reward_source: "world_verifier",
        failure_codes: reward === 1 ? [] : ["incomplete_workflow"],
        sha256: "sha256:audit",
      },
      run_export_sha256: "sha256:run",
    },
  };
}

test("agent aliases are provider-safe and cover policy traps", () => {
  const aliases = selectedToolAliases();
  assert.ok(Object.keys(aliases).length >= 16);
  for (const alias of Object.keys(aliases)) {
    assert.match(alias, /^[A-Za-z0-9_-]+$/);
  }
  assert.equal(aliases.stripe_create_refund, "billing_stripe.create_refund");
  assert.equal(aliases.graph_send_message, "communications_graph.send_message");
});

test("published Docker ports are parsed strictly", () => {
  assert.equal(parsePublishedPort("127.0.0.1:49152\n"), 49_152);
  assert.throws(() => parsePublishedPort("0.0.0.0:49152"));
});

test("the Mastra scorer uses the hidden world reward", async () => {
  const passed = await worldStateScorer.run({
    input: { prompt: "complete the task" },
    output: output(1),
  });
  const failed = await worldStateScorer.run({
    input: { prompt: "complete the task" },
    output: output(0),
  });
  const agentError = output(1);
  agentError.agentError = { name: "Error", message: "model call failed" };
  const errored = await worldStateScorer.run({
    input: { prompt: "complete the task" },
    output: agentError,
  });

  assert.equal(passed.score, 1);
  assert.equal(failed.score, 0);
  assert.equal(errored.score, 0);
});
