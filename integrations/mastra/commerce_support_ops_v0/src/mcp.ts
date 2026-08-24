import { RequestContext } from "@mastra/core/request-context";
import { Tool } from "@mastra/core/tools";
import { MCPClient } from "@mastra/mcp";

export type MCPToolMap = Awaited<ReturnType<MCPClient["listTools"]>>;

const TOOL_ALIASES = {
  world_get_task: "billing_get_task",
  stripe_list_customers: "billing_stripe.list_customers",
  stripe_list_payment_intents: "billing_stripe.list_payment_intents",
  stripe_create_refund: "billing_stripe.create_refund",
  stripe_capture_payment: "billing_stripe.capture_payment",
  commerce_list_orders: "support_commerce.list_orders",
  hubspot_list_tickets: "support_hubspot.list_tickets",
  hubspot_update_ticket: "support_hubspot.update_ticket",
  workflow_record_no_call: "support_workflow.record_no_call",
  workflow_commit_handoff: "support_workflow.commit_handoff",
  commerce_cancel_order: "support_commerce.cancel_order",
  commerce_delete_order: "support_commerce.delete_order",
  jira_get_issue: "engineering_jira.get_issue",
  jira_update_issue: "engineering_jira.update_issue",
  graph_get_calendar: "communications_graph.get_calendar",
  graph_create_draft: "communications_graph.create_draft",
  graph_send_message: "communications_graph.send_message",
} as const;

export function createMcpClient(baseUrl: string): MCPClient {
  return new MCPClient({
    id: "datalox-commerce-support",
    servers: {
      billing: {
        url: new URL(`${baseUrl}/actors/billing_specialist/mcp`),
      },
      support: {
        url: new URL(`${baseUrl}/actors/support_owner/mcp`),
      },
      engineering: {
        url: new URL(`${baseUrl}/actors/engineering_owner/mcp`),
      },
      communications: {
        url: new URL(`${baseUrl}/actors/communications_owner/mcp`),
      },
    },
  });
}

export function selectAgentTools(rawTools: MCPToolMap): Record<string, Tool> {
  const selected: Record<string, Tool> = {};
  for (const [alias, sourceName] of Object.entries(TOOL_ALIASES)) {
    const source = rawTools[sourceName];
    if (!source?.execute) {
      throw new Error(`required MCP tool is unavailable: ${sourceName}`);
    }
    const execute = source.execute;
    selected[alias] = new Tool({
      id: alias,
      description: source.description,
      ...(source.inputSchema ? { inputSchema: source.inputSchema } : {}),
      ...(source.outputSchema ? { outputSchema: source.outputSchema } : {}),
      execute: async (inputData, context) =>
        execute(inputData, context as never),
    });
  }
  return selected;
}

export async function invokeTool(
  tools: MCPToolMap,
  name: string,
  input: Record<string, unknown>,
): Promise<unknown> {
  const tool = tools[name];
  if (!tool?.execute) {
    throw new Error(`MCP tool is unavailable: ${name}`);
  }
  const result = await tool.execute(
    input,
    { requestContext: new RequestContext() } as never,
  );
  if (
    typeof result === "object" &&
    result !== null &&
    "isError" in result &&
    result.isError === true
  ) {
    throw new Error(`MCP tool failed: ${name}`);
  }
  return result;
}

export function selectedToolAliases(): Readonly<Record<string, string>> {
  return TOOL_ALIASES;
}
