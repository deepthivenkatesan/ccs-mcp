// index.ts
//
// CCS MCP Gateway: one Worker, many MCP connectors, one per URL path.
//
// This Worker speaks OAuth 2.1 (with dynamic client registration) to the MCP
// client, authenticates the human through the dedicated "CCS MCP Gateway
// (ccs-mcp)" Cloudflare Access SaaS/OIDC application, and then serves MCP
// itself. Unlike the older backend pattern there is no second hop: no tunnel,
// no service token, no separate Node service.
//
// Adding a connector is a directory under src/servers/ plus one line in
// REGISTRY below.

import {
  OAuthProvider,
  AuthorizationError,
  type AuthRequest,
} from "@cloudflare/workers-oauth-provider";

import type { Env } from "./types";
import { verifyAccessIdToken } from "./verifyIdToken";
import { getProps, type AccessProps } from "./mcp/props";
import { handleMcpRequest, type McpServerDef } from "./mcp/transport";
import { createSelftestServer } from "./servers/selftest/server";

// ---------- The registry ----------

interface ConnectorEntry {
  /** URL path this connector is served at, e.g. "/selftest". */
  path: string;
  /** One line, shown on /status. */
  description: string;
  /** Builds a fresh MCP server per request. */
  createServer: (env: Env, props: AccessProps) => McpServerDef;
}

const REGISTRY: ConnectorEntry[] = [
  {
    path: "/selftest",
    description:
      "No-vendor health connector. Confirms OAuth, routing and identity without needing a vendor credential.",
    createServer: createSelftestServer,
  },
];

const CONNECTOR_PATHS = REGISTRY.map((entry) => entry.path);

const SCOPES = ["mcp:read", "mcp:write"];

// ---------- /authorize, /callback, /status (defaultHandler) ----------

const defaultHandler: ExportedHandler<Env> = {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/authorize") return handleAuthorize(request, env);
    if (url.pathname === "/callback") return handleCallback(request, env);

    // Unauthenticated, deliberately. Answers "is the Worker up and did the
    // registry load" in one request, and says which slot you are talking to.
    if (url.pathname === "/status") {
      return Response.json(
        {
          service: "ccs-mcp",
          environment: env.ENVIRONMENT,
          gateway_base_url: env.GATEWAY_BASE_URL,
          connectors: REGISTRY.map((entry) => ({
            path: entry.path,
            description: entry.description,
          })),
          connector_count: REGISTRY.length,
          time: new Date().toISOString(),
        },
        { headers: { "cache-control": "no-store" } }
      );
    }

    if (url.pathname === "/") {
      return new Response(
        `CCS MCP gateway (${env.ENVIRONMENT}). Not a browsable app. See /status.`,
        { status: 200, headers: { "content-type": "text/plain" } }
      );
    }

    return new Response("Not found", { status: 404 });
  },
};

async function handleAuthorize(request: Request, env: Env): Promise<Response> {
  let oauthRequest: AuthRequest;
  try {
    oauthRequest = await env.OAUTH_PROVIDER.parseAuthRequest(request);
  } catch (error) {
    if (!(error instanceof AuthorizationError)) throw error;
    if (!error.redirectUri) return new Response(error.description, { status: 400 });
    const redirect = new URL(error.redirectUri);
    redirect.searchParams.set("error", error.code);
    redirect.searchParams.set("error_description", error.description);
    if (error.state) redirect.searchParams.set("state", error.state);
    return Response.redirect(redirect.toString(), 302);
  }

  const client = await env.OAUTH_PROVIDER.lookupClient(oauthRequest.clientId);
  if (!client) return new Response("Unknown OAuth client", { status: 400 });

  // Fail fast rather than bouncing the human through a login that cannot
  // complete: an unset client secret otherwise surfaces as a confusing
  // error from Access at the token exchange.
  if (!env.ACCESS_OIDC_CLIENT_SECRET) {
    return new Response(
      "ACCESS_OIDC_CLIENT_SECRET is not set on this Worker. Set it with: npx wrangler secret put ACCESS_OIDC_CLIENT_SECRET --env staging",
      { status: 500 }
    );
  }

  // Stash the parsed request behind a one-time nonce while the human
  // authenticates at Access, then pass the nonce as `state`.
  const nonce = crypto.randomUUID();
  await env.PENDING_AUTH_KV.put(nonce, JSON.stringify(oauthRequest), {
    expirationTtl: 600,
  });

  const accessAuthorizeUrl = new URL(env.ACCESS_OIDC_AUTHORIZATION_URL);
  accessAuthorizeUrl.searchParams.set("response_type", "code");
  accessAuthorizeUrl.searchParams.set("client_id", env.ACCESS_OIDC_CLIENT_ID);
  accessAuthorizeUrl.searchParams.set("redirect_uri", `${env.GATEWAY_BASE_URL}/callback`);
  accessAuthorizeUrl.searchParams.set("scope", "openid email profile");
  accessAuthorizeUrl.searchParams.set("state", nonce);

  return Response.redirect(accessAuthorizeUrl.toString(), 302);
}

async function handleCallback(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const nonce = url.searchParams.get("state");
  const accessError = url.searchParams.get("error");

  if (accessError) {
    return new Response(`Access login failed: ${accessError}`, { status: 400 });
  }
  if (!code || !nonce) {
    return new Response("Missing code or state from Access callback", { status: 400 });
  }

  const pendingRaw = await env.PENDING_AUTH_KV.get(nonce);
  if (!pendingRaw) {
    return new Response(
      "Login session expired or already used. Please retry from your MCP client.",
      { status: 400 }
    );
  }
  await env.PENDING_AUTH_KV.delete(nonce); // single use

  const oauthRequest = JSON.parse(pendingRaw) as AuthRequest;

  const tokenRes = await fetch(env.ACCESS_OIDC_TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: `${env.GATEWAY_BASE_URL}/callback`,
      client_id: env.ACCESS_OIDC_CLIENT_ID,
      client_secret: env.ACCESS_OIDC_CLIENT_SECRET,
    }),
  });

  if (!tokenRes.ok) {
    const body = await tokenRes.text();
    return new Response(`Access token exchange failed (${tokenRes.status}): ${body}`, {
      status: 502,
    });
  }

  const tokenJson = (await tokenRes.json()) as { id_token?: string };
  if (!tokenJson.id_token) {
    return new Response("Access token response did not include an id_token", { status: 502 });
  }

  let claims;
  try {
    claims = await verifyAccessIdToken(tokenJson.id_token, {
      jwksUrl: env.ACCESS_OIDC_JWKS_URL,
      expectedIssuer: env.ACCESS_OIDC_ISSUER,
      expectedAudience: env.ACCESS_OIDC_CLIENT_ID,
    });
  } catch (err) {
    return new Response(`id_token verification failed: ${(err as Error).message}`, {
      status: 401,
    });
  }

  const email = claims.email;
  if (!email || typeof email !== "string") {
    return new Response("id_token did not include an email claim", { status: 401 });
  }
  if (
    env.ALLOWED_EMAIL_DOMAIN &&
    !email.toLowerCase().endsWith(`@${env.ALLOWED_EMAIL_DOMAIN.toLowerCase()}`)
  ) {
    return new Response(`${email} is not authorized for this gateway`, { status: 403 });
  }

  const props: AccessProps = { email };
  const { redirectTo } = await env.OAUTH_PROVIDER.completeAuthorization({
    request: oauthRequest,
    userId: email,
    metadata: { email },
    scope: oauthRequest.scope.filter((s) => SCOPES.includes(s)),
    props,
  });

  return Response.redirect(redirectTo, 302);
}

// ---------- Connector routing (apiHandler) ----------
//
// The OAuth provider only invokes this once it has validated the bearer
// token, so anything reaching here is authenticated. The registry decides
// which connector answers.

const apiHandler = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const props = getProps(ctx);
    if (!props) {
      return new Response("Unauthorized", { status: 401 });
    }

    const pathname = new URL(request.url).pathname;
    const entry = REGISTRY.find((candidate) => candidate.path === pathname);
    if (!entry) {
      return Response.json(
        {
          error: "unknown_connector",
          message: `No connector is registered at ${pathname}.`,
          registered: CONNECTOR_PATHS,
        },
        { status: 404 }
      );
    }

    const server = entry.createServer(env, props);
    return handleMcpRequest(request, server, props);
  },
};

// ---------- Provider wiring ----------

export default new OAuthProvider<Env>({
  // Every connector path is an API route, so the provider enforces the
  // bearer token on each one independently.
  apiRoute: CONNECTOR_PATHS,
  apiHandler,
  defaultHandler,

  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",

  scopesSupported: SCOPES,
});
