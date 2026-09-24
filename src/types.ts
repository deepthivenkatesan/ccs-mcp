// types.ts
//
// The Env interface: every var and secret the gateway reads.
// Non-secret configuration lives in wrangler.jsonc as plain vars.
// Everything else is a Worker secret, set with `wrangler secret put`.

import type { OAuthHelpers } from "@cloudflare/workers-oauth-provider";

export interface Env {
  // Owned exclusively by @cloudflare/workers-oauth-provider.
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: OAuthHelpers;

  // Pending-authorization state while the human is at Cloudflare Access.
  // Deliberately a separate namespace from OAUTH_KV.
  PENDING_AUTH_KV: KVNamespace;

  // The dedicated "CCS MCP Gateway (ccs-mcp)" Access SaaS/OIDC application.
  // Copied verbatim from that app's OIDC tab — do not guess the URL shape.
  ACCESS_OIDC_ISSUER: string;
  ACCESS_OIDC_AUTHORIZATION_URL: string;
  ACCESS_OIDC_TOKEN_URL: string;
  ACCESS_OIDC_JWKS_URL: string;
  ACCESS_OIDC_CLIENT_ID: string;

  // Secret. Shown once by Cloudflare at app creation.
  ACCESS_OIDC_CLIENT_SECRET: string;

  // This Worker's own public URL, used to build the redirect_uri Access
  // sends the human back to. Must match a redirect URI registered on the
  // Access application, or login fails.
  GATEWAY_BASE_URL: string;

  // Which environment this deploy is. Surfaced on /status so it is always
  // possible to tell which slot you are actually talking to.
  ENVIRONMENT: string;

  // Optional allow-list. If set, only emails on this domain complete login.
  ALLOWED_EMAIL_DOMAIN?: string;

  // ---- Liongard connector ----
  // Origin only; the client appends paths that already begin with /api/.
  LIONGARD_BASE_URL: string;
  // Secrets. Sent as X-ROAR-API-KEY: base64(id:secret).
  // The key inherits the permissions of the Liongard user that minted it, so
  // the read-only ceiling lives in Liongard's console, not in this code.
  LIONGARD_ACCESS_KEY_ID: string;
  LIONGARD_ACCESS_KEY_SECRET: string;

  // ---- Acumatica connector ----
  // Vars. Origin only, e.g. https://sunoilbahamas-sandbox.acumatica.com, and
  // the tenant (company) string login expects, e.g. "FOCOL Holdings Ltd".
  ACUMATICA_BASE_URL: string;
  ACUMATICA_TENANT: string;
  // Secrets. The service account's username and password, used for a cookie
  // session per call (login -> GET -> logout). Its roles, not this code, are
  // the read-only ceiling at Acumatica.
  ACUMATICA_USERNAME: string;
  ACUMATICA_PASSWORD: string;
}
