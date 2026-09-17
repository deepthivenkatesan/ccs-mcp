// sdkBridge.ts
//
// Lets this gateway host connectors written against the official MCP SDK
// (`McpServer` + `server.registerTool`) alongside the lightweight McpServerDef
// used by first-party connectors.
//
// Why this exists: the Liongard connector was handed over from the Platinum
// gateway as working production code, with notes warning that its complexity is
// deliberate and paid for. Rewriting ~400 lines of size-capping and metric
// chunking logic into our own shape would be the single most likely place to
// reintroduce those bugs. So the gateway adapts to the code, not the reverse.
//
// The SDK expects a Transport it can talk to. Ours is stateless: we feed in the
// messages from one HTTP request, collect the responses the server emits, and
// return them. No session survives the request, so no Durable Object is needed.

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import type { JSONRPCMessage } from "@modelcontextprotocol/sdk/types.js";

import type { Env } from "../types";
import type { AccessProps } from "./props";

export type SdkServerFactory = (env: Env, props: AccessProps) => McpServer;

/** How long to wait for a server to answer everything in one request. */
const RESPONSE_TIMEOUT_MS = 25_000;

/**
 * A Transport that exists for the life of one HTTP request. Inbound messages
 * are pushed in with deliver(); outbound ones are buffered until the expected
 * number of responses has arrived, or the timeout fires.
 */
class RequestScopedTransport implements Transport {
  onmessage?: (message: JSONRPCMessage, extra?: unknown) => void;
  onclose?: () => void;
  onerror?: (error: Error) => void;
  sessionId?: string;

  private readonly outbound: JSONRPCMessage[] = [];
  private readonly waiters = new Set<() => void>();

  async start(): Promise<void> {
    // Nothing to open: the HTTP request is the connection.
  }

  async close(): Promise<void> {
    this.onclose?.();
  }

  /** Called by the SDK when the server wants to emit a message. */
  async send(message: JSONRPCMessage): Promise<void> {
    this.outbound.push(message);
    for (const notify of [...this.waiters]) notify();
  }

  /** Push a client message into the server. */
  deliver(message: JSONRPCMessage): void {
    this.onmessage?.(message);
  }

  /** Resolve once `expected` responses have been emitted, or on timeout. */
  collect(expected: number, timeoutMs: number): Promise<JSONRPCMessage[]> {
    if (this.outbound.length >= expected) return Promise.resolve([...this.outbound]);

    return new Promise((resolve) => {
      const finish = () => {
        clearTimeout(timer);
        this.waiters.delete(check);
        resolve([...this.outbound]);
      };
      const check = () => {
        if (this.outbound.length >= expected) finish();
      };
      const timer = setTimeout(finish, timeoutMs);
      this.waiters.add(check);
    });
  }
}

function isRequest(message: JSONRPCMessage): boolean {
  const m = message as { method?: unknown; id?: unknown };
  return typeof m.method === "string" && m.id !== undefined && m.id !== null;
}

/**
 * Handles one HTTP request against an SDK-based connector. The caller is
 * already authenticated: the OAuth provider will not route here without a
 * valid bearer token.
 */
export async function handleSdkMcpRequest(
  request: Request,
  createServer: SdkServerFactory,
  env: Env,
  props: AccessProps
): Promise<Response> {
  if (request.method !== "POST") {
    return new Response("Method not allowed. MCP Streamable HTTP expects POST.", {
      status: 405,
      headers: { allow: "POST" },
    });
  }

  let body: unknown;
  try {
    body = await request.json();
  } catch {
    return Response.json(
      { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error: body was not valid JSON" } },
      { status: 400 }
    );
  }

  const batched = Array.isArray(body);
  const messages = (batched ? body : [body]) as JSONRPCMessage[];
  const expected = messages.filter(isRequest).length;

  const server = createServer(env, props);
  const transport = new RequestScopedTransport();
  await server.connect(transport);

  try {
    for (const message of messages) transport.deliver(message);

    // Everything was a notification: nothing to answer.
    if (expected === 0) return new Response(null, { status: 202 });

    const responses = await transport.collect(expected, RESPONSE_TIMEOUT_MS);

    if (responses.length === 0) {
      return Response.json(
        { jsonrpc: "2.0", id: null, error: { code: -32603, message: "Connector produced no response within the request timeout" } },
        { status: 504 }
      );
    }

    return Response.json(batched ? responses : responses[0], {
      status: 200,
      headers: { "cache-control": "no-store" },
    });
  } finally {
    // Stateless: the server does not outlive the request it answered.
    await server.close().catch(() => {});
  }
}
