/**
 * Liongard MCP server factory.
 *
 * Fresh McpServer per request (SDK >= 1.26). Read-only configuration
 * intelligence. Direct-to-vendor: the Worker calls Liongard's public API
 * itself, which is the gateway pattern — see the MCP Platform book.
 *
 * Handed over from the Platinum gateway on 14 Sep 2026. `client.ts`,
 * `tools.ts` and `schemas.ts` are unmodified from that handover apart from one
 * stale operator hint in a `client.ts` error string; their complexity is
 * deliberate and documented. This file is the only one rewired for CCS: the
 * caller identity now comes from Cloudflare Access via the gateway's OAuth
 * grant rather than from Platinum's Entra props.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Env } from "../../types";
import type { McpProps } from "../../mcp/props";
import { registerLiongardTools } from "./tools";

export function createLiongardServer(env: Env, props: McpProps): McpServer {
  const server = new McpServer({
    name: "liongard",
    version: "1.0.0",
  });
  registerLiongardTools(server, env, props);
  return server;
}
