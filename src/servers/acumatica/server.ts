/**
 * Acumatica MCP server factory.
 *
 * Fresh McpServer per request (SDK >= 1.26), hosted through sdkBridge.ts.
 * Read-only business data from the FOCOL / Sun Oil Acumatica sandbox,
 * direct-to-vendor: the Worker calls Acumatica's contract-based REST API
 * itself. Built for CCS on 24 Sep 2026; see the "Acumatica (in progress)"
 * page in the MCP Platform book for decisions, probe results and quirks.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Env } from "../../types";
import type { McpProps } from "../../mcp/props";
import { registerAcumaticaTools } from "./tools";

export function createAcumaticaServer(env: Env, props: McpProps): McpServer {
  const server = new McpServer({
    name: "acumatica",
    version: "0.1.0",
  });
  registerAcumaticaTools(server, env, props);
  return server;
}
