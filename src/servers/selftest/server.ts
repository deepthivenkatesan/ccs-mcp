// servers/selftest/server.ts
//
// A connector with no vendor dependency. It exists so the gateway can be
// verified end to end — OAuth, routing, transport, and the identity that
// reaches a connector — without needing any vendor credential to be in place
// first. It stays useful afterwards as a health check: if a client can call
// `whoami` here but a real connector fails, the problem is that connector,
// not the gateway.

import type { Env } from "../../types";
import type { AccessProps } from "../../mcp/props";
import type { McpServerDef } from "../../mcp/transport";

export function createSelftestServer(env: Env, props: AccessProps): McpServerDef {
  return {
    name: "ccs-selftest",
    version: "1.0.0",
    tools: [
      {
        name: "whoami",
        description:
          "Returns the identity Cloudflare Access authenticated for this session, and which gateway environment answered. Use this to confirm the connector is reaching the environment you expect.",
        inputSchema: { type: "object", properties: {}, additionalProperties: false },
        handler: async (_args, caller) => [
          {
            type: "text" as const,
            text: JSON.stringify(
              {
                email: caller.email,
                environment: env.ENVIRONMENT,
                gateway_base_url: env.GATEWAY_BASE_URL,
                allowed_email_domain: env.ALLOWED_EMAIL_DOMAIN ?? null,
                server_time: new Date().toISOString(),
              },
              null,
              2
            ),
          },
        ],
      },
    ],
  };
}
