// transport.ts
//
// MCP over Streamable HTTP, stateless.
//
// Each request is self-contained: the client POSTs JSON-RPC, the Worker
// answers with application/json. No session is held between requests and no
// Durable Object is involved, which is what lets one Worker serve every
// connector without per-connector infrastructure.
//
// Notifications get 202 with no body, per the Streamable HTTP spec.

import type { AccessProps } from "./props";

export type McpContent = { type: "text"; text: string };

export interface McpTool {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  handler: (args: Record<string, unknown>, props: AccessProps) => Promise<McpContent[]>;
}

export interface McpServerDef {
  name: string;
  version: string;
  tools: McpTool[];
}

/** Protocol versions this transport implements, newest first. */
const SUPPORTED_PROTOCOL_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"];

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
}

function rpcResult(id: string | number | null | undefined, result: unknown) {
  return { jsonrpc: "2.0" as const, id: id ?? null, result };
}

function rpcError(id: string | number | null | undefined, code: number, message: string) {
  return { jsonrpc: "2.0" as const, id: id ?? null, error: { code, message } };
}

async function dispatch(
  message: JsonRpcRequest,
  server: McpServerDef,
  props: AccessProps
): Promise<object | null> {
  const { method, id, params } = message;

  switch (method) {
    case "initialize": {
      const requested = (params?.protocolVersion as string) ?? "";
      const protocolVersion = SUPPORTED_PROTOCOL_VERSIONS.includes(requested)
        ? requested
        : SUPPORTED_PROTOCOL_VERSIONS[0];
      return rpcResult(id, {
        protocolVersion,
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: server.name, version: server.version },
      });
    }

    // Notifications carry no id and expect no response body.
    case "notifications/initialized":
    case "notifications/cancelled":
      return null;

    case "ping":
      return rpcResult(id, {});

    case "tools/list":
      return rpcResult(id, {
        tools: server.tools.map((tool) => ({
          name: tool.name,
          description: tool.description,
          inputSchema: tool.inputSchema,
        })),
      });

    case "tools/call": {
      const name = params?.name as string;
      const tool = server.tools.find((t) => t.name === name);
      if (!tool) {
        return rpcError(id, -32602, `Unknown tool: ${name}`);
      }
      const args = (params?.arguments as Record<string, unknown>) ?? {};
      try {
        const content = await tool.handler(args, props);
        return rpcResult(id, { content, isError: false });
      } catch (err) {
        // Tool failures are reported in-band so the model can see and react
        // to them, rather than surfacing as a transport-level error.
        return rpcResult(id, {
          content: [{ type: "text", text: `Error: ${(err as Error).message}` }],
          isError: true,
        });
      }
    }

    default:
      if (method && method.startsWith("notifications/")) return null;
      return rpcError(id, -32601, `Method not found: ${method}`);
  }
}

/**
 * Handles one HTTP request against a connector's MCP server.
 * The caller is already authenticated: the OAuth provider will not route
 * here without a valid bearer token.
 */
export async function handleMcpRequest(
  request: Request,
  server: McpServerDef,
  props: AccessProps
): Promise<Response> {
  if (request.method !== "POST") {
    // Stateless: there is no server-initiated stream to open on GET.
    return new Response("Method not allowed. MCP Streamable HTTP expects POST.", {
      status: 405,
      headers: { allow: "POST" },
    });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json(rpcError(null, -32700, "Parse error: body was not valid JSON"), {
      status: 400,
    });
  }

  // A client may batch messages in an array.
  const messages = Array.isArray(body) ? body : [body];
  const responses: object[] = [];

  for (const message of messages as JsonRpcRequest[]) {
    const response = await dispatch(message, server, props);
    if (response) responses.push(response);
  }

  if (responses.length === 0) {
    // Everything in the batch was a notification.
    return new Response(null, { status: 202 });
  }

  return Response.json(Array.isArray(body) ? responses : responses[0], {
    status: 200,
    headers: { "cache-control": "no-store" },
  });
}
