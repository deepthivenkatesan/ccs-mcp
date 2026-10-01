/**
 * Per-user Acumatica sign-in (decision 1, MCP Platform book, "Acumatica (in progress)").
 *
 * Connect-on-first-use. A tool call from a person with no Acumatica tokens returns a
 * one-time link to START_PATH. That redirects to Acumatica's own sign-in page
 * (Authorization Code + PKCE S256); Acumatica returns to CALLBACK_PATH, which exchanges
 * the code and stores the person's tokens, encrypted, keyed by the email Cloudflare
 * Access verified. Every later call runs as that person, so Acumatica enforces their
 * roles. The gateway's shared /authorize and /callback are not touched.
 *
 * Both routes live OUTSIDE /acumatica on purpose: the OAuth provider treats every path
 * under a connector path as a protected API route (verified 1 Oct 2026: GET
 * /acumatica/oauth/callback -> 401), so Acumatica's redirect would never reach us there.
 *
 * VERIFIED by probe on the sandbox, 1 Oct 2026, not assumed:
 *  - endpoints below (from /identity/.well-known/openid-configuration)
 *  - code exchange with client_secret_post + code_verifier -> 200, 3600 s Bearer,
 *    refresh token with offline_access; opaque 43-char access token
 *  - bearer API calls set no session cookie (no login/logout needed)
 *  - refresh rotates the refresh token; the old one -> 400 invalid_grant
 *  - an access token outlives a refresh (still 200 afterwards)
 *  - revoking a REFRESH token returns 500 NotImplementedException, yet a later refresh
 *    gets invalid_grant. Revoking an ACCESS token -> 200, then API 401. So: revoke both,
 *    then confirm with a refresh attempt; never trust the revocation status alone.
 *  - userinfo (scope openid) returns only `sub`, e.g. "<login>@<tenant>"
 * NOT verified: whether Acumatica honours prompt=login; refresh-token lifetime.
 */

import type { Env } from "../../types";

export const START_PATH = "/oauth/acumatica/start";
export const CALLBACK_PATH = "/oauth/acumatica/callback";

const AUTHORIZE_PATH = "/identity/connect/authorize";
const TOKEN_PATH = "/identity/connect/token";
const REVOKE_PATH = "/identity/connect/revocation";
const USERINFO_PATH = "/identity/connect/userinfo";
const SCOPE = "openid api offline_access";

/** Connect tickets and in-flight sign-ins live in PENDING_AUTH_KV under this prefix. */
const TICKET_PREFIX = "acu:ticket:";
const FLOW_PREFIX = "acu:flow:";
const TICKET_TTL_S = 600;
/** Per-person token records live in ACUMATICA_TOKENS_KV under this prefix. */
const TOKEN_PREFIX = "acu:tokens:";
/** Refresh this many seconds before the access token's stated expiry. */
const REFRESH_SKEW_S = 60;
const FETCH_TIMEOUT_MS = 15_000;

export type AuthMode = "user" | "service";

export function authMode(env: Env): AuthMode {
  return env.ACUMATICA_AUTH_MODE === "user" ? "user" : "service";
}

type TokenRecord = {
  access_token: string;
  refresh_token?: string;
  /** Epoch seconds. */
  expires_at: number;
  /** Acumatica's `sub` from userinfo, e.g. "jsmith@FOCOL Holdings Ltd". */
  acumatica_login?: string;
  linked_at: string;
};

/** Thrown when a person has no usable Acumatica tokens. The message carries the link. */
export class NotConnectedError extends Error {}

// ---------- configuration ----------

export function requireOAuthConfig(env: Env): void {
  const missing = [
    ["ACUMATICA_BASE_URL", env.ACUMATICA_BASE_URL],
    ["GATEWAY_BASE_URL", env.GATEWAY_BASE_URL],
    ["ACUMATICA_OAUTH_CLIENT_ID", env.ACUMATICA_OAUTH_CLIENT_ID],
    ["ACUMATICA_OAUTH_CLIENT_SECRET", env.ACUMATICA_OAUTH_CLIENT_SECRET],
    ["ACUMATICA_TOKEN_KEY", env.ACUMATICA_TOKEN_KEY],
    ["ACUMATICA_TOKENS_KV (binding)", env.ACUMATICA_TOKENS_KV],
    ["PENDING_AUTH_KV (binding)", env.PENDING_AUTH_KV],
  ].filter(([, v]) => !v).map(([n]) => n);
  if (missing.length) {
    throw new Error(
      `Acumatica per-user sign-in is not configured on this Worker: ${missing.join(", ")} unset. ` +
        "Secrets are set from CT 126 with `wrangler secret put <n> --env staging`; the KV binding " +
        "is in wrangler.jsonc. Check the untruncated `wrangler secret list` and the deploy's binding summary.",
    );
  }
}

const base = (env: Env) => env.ACUMATICA_BASE_URL.replace(/\/+$/, "");
const redirectUri = (env: Env) => `${env.GATEWAY_BASE_URL.replace(/\/+$/, "")}${CALLBACK_PATH}`;
const tokenKey = (email: string) => TOKEN_PREFIX + email.trim().toLowerCase();

// ---------- small helpers ----------

function b64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function b64url(bytes: Uint8Array): string {
  return b64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function randomToken(nBytes = 32): string {
  return b64url(crypto.getRandomValues(new Uint8Array(nBytes)));
}
function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}
/** RFC 6749 2.3.1: form-urlencode client_id and secret before Basic encoding (verified working, probe 3). */
function basicAuth(env: Env): string {
  const f = (s: string) => encodeURIComponent(s).replace(/%20/g, "+");
  return "Basic " + btoa(`${f(env.ACUMATICA_OAUTH_CLIENT_ID!)}:${f(env.ACUMATICA_OAUTH_CLIENT_SECRET!)}`);
}
function page(title: string, body: string, status = 200): Response {
  const html =
    `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">` +
    `<title>${escapeHtml(title)}</title><style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;line-height:1.5}</style>` +
    `</head><body><h1>${escapeHtml(title)}</h1>${body}</body></html>`;
  return new Response(html, { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}
async function postForm(env: Env, path: string, form: Record<string, string>, auth?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" };
  if (auth) headers.Authorization = auth;
  const res = await fetch(base(env) + path, {
    method: "POST", headers, body: new URLSearchParams(form).toString(), signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
  });
  const text = await res.text();
  let json: Record<string, unknown> = {};
  try { json = JSON.parse(text); } catch { /* revocation 500s are HTML */ }
  return { status: res.status, ok: res.ok, json };
}

// ---------- encrypted token storage ----------

async function aesKey(env: Env): Promise<CryptoKey> {
  const raw = unb64(env.ACUMATICA_TOKEN_KEY!);
  if (raw.length !== 32) throw new Error("ACUMATICA_TOKEN_KEY must be base64 of exactly 32 bytes.");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

/** AES-256-GCM, with the email as associated data so a record cannot be moved to another key. */
async function saveRecord(env: Env, email: string, rec: TokenRecord): Promise<void> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ad = new TextEncoder().encode(tokenKey(email));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: ad }, await aesKey(env), new TextEncoder().encode(JSON.stringify(rec)),
  ));
  await env.ACUMATICA_TOKENS_KV!.put(tokenKey(email), JSON.stringify({ v: 1, iv: b64(iv), ct: b64(ct) }));
}

async function loadRecord(env: Env, email: string): Promise<TokenRecord | null> {
  const raw = await env.ACUMATICA_TOKENS_KV!.get(tokenKey(email));
  if (!raw) return null;
  try {
    const { iv, ct } = JSON.parse(raw) as { iv: string; ct: string };
    const ad = new TextEncoder().encode(tokenKey(email));
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv), additionalData: ad }, await aesKey(env), unb64(ct));
    return JSON.parse(new TextDecoder().decode(pt)) as TokenRecord;
  } catch {
    // Unreadable (key rotated, or tampered): treat as not connected rather than fail every call.
    await env.ACUMATICA_TOKENS_KV!.delete(tokenKey(email));
    return null;
  }
}

async function deleteRecord(env: Env, email: string): Promise<void> {
  await env.ACUMATICA_TOKENS_KV!.delete(tokenKey(email));
}

function recordFrom(json: Record<string, unknown>, login: string | undefined, linkedAt: string, prevRefresh?: string): TokenRecord {
  const expiresIn = Number(json.expires_in ?? 3600);
  return {
    access_token: String(json.access_token),
    refresh_token: typeof json.refresh_token === "string" ? json.refresh_token : prevRefresh,
    expires_at: Math.floor(Date.now() / 1000) + (Number.isFinite(expiresIn) ? expiresIn : 3600),
    acumatica_login: login,
    linked_at: linkedAt,
  };
}

// ---------- connect link ----------

/** A single-use, 10-minute link bound to this person's verified email. */
export async function connectLink(env: Env, email: string): Promise<string> {
  requireOAuthConfig(env);
  const ticket = randomToken();
  await env.PENDING_AUTH_KV.put(TICKET_PREFIX + ticket, JSON.stringify({ email }), { expirationTtl: TICKET_TTL_S });
  return `${env.GATEWAY_BASE_URL.replace(/\/+$/, "")}${START_PATH}?t=${ticket}`;
}

export async function notConnected(env: Env, email: string, reason: string): Promise<NotConnectedError> {
  const link = await connectLink(env, email);
  return new NotConnectedError(
    `${reason} Connect your Acumatica account by opening this link and signing in as yourself ` +
      `(single use, valid 10 minutes): ${link} ... then ask again.`,
  );
}

// ---------- routes (served by the gateway's open handler, not under /acumatica) ----------

export async function handleStart(request: Request, env: Env): Promise<Response> {
  try { requireOAuthConfig(env); } catch (e) { return page("Acumatica sign-in is not configured", `<p>${escapeHtml((e as Error).message)}</p>`, 500); }
  const ticket = new URL(request.url).searchParams.get("t") ?? "";
  const raw = ticket ? await env.PENDING_AUTH_KV.get(TICKET_PREFIX + ticket) : null;
  if (!raw) {
    return page("This link has expired", "<p>Connect links work once and only for 10 minutes. Ask Claude again for a new one.</p>", 400);
  }
  await env.PENDING_AUTH_KV.delete(TICKET_PREFIX + ticket); // single use
  const { email } = JSON.parse(raw) as { email: string };

  const verifier = randomToken(48);
  const challenge = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier))));
  const state = randomToken();
  await env.PENDING_AUTH_KV.put(FLOW_PREFIX + state, JSON.stringify({ email, verifier }), { expirationTtl: TICKET_TTL_S });

  const u = new URL(base(env) + AUTHORIZE_PATH);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", env.ACUMATICA_OAUTH_CLIENT_ID!);
  u.searchParams.set("redirect_uri", redirectUri(env));
  u.searchParams.set("scope", SCOPE);
  u.searchParams.set("state", state);
  u.searchParams.set("code_challenge", challenge);
  u.searchParams.set("code_challenge_method", "S256");
  // Ask for a fresh sign-in so a browser already signed in as someone else is not reused.
  // Whether Acumatica honours this is unverified; the confirmation page shows the linked login either way.
  u.searchParams.set("prompt", "login");
  return Response.redirect(u.toString(), 302);
}

export async function handleCallback(request: Request, env: Env): Promise<Response> {
  try { requireOAuthConfig(env); } catch (e) { return page("Acumatica sign-in is not configured", `<p>${escapeHtml((e as Error).message)}</p>`, 500); }
  const url = new URL(request.url);
  const err = url.searchParams.get("error");
  if (err) {
    const desc = url.searchParams.get("error_description") ?? "";
    return page("Acumatica sign-in did not complete", `<p>Acumatica returned <code>${escapeHtml(err)}</code>${desc ? `: ${escapeHtml(desc)}` : ""}.</p><p>Ask Claude for a new connect link to try again.</p>`, 400);
  }
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const raw = state ? await env.PENDING_AUTH_KV.get(FLOW_PREFIX + state) : null;
  if (!code || !raw) {
    return page("This sign-in has expired", "<p>The sign-in took too long or was already used. Ask Claude for a new connect link.</p>", 400);
  }
  await env.PENDING_AUTH_KV.delete(FLOW_PREFIX + state!); // single use
  const { email, verifier } = JSON.parse(raw) as { email: string; verifier: string };

  // Code exchange: client_secret_post with the PKCE verifier, as verified by probe.
  const tok = await postForm(env, TOKEN_PATH, {
    grant_type: "authorization_code", code, redirect_uri: redirectUri(env),
    client_id: env.ACUMATICA_OAUTH_CLIENT_ID!, client_secret: env.ACUMATICA_OAUTH_CLIENT_SECRET!, code_verifier: verifier,
  });
  if (!tok.ok || typeof tok.json.access_token !== "string") {
    const why = [tok.json.error, tok.json.error_description].filter(Boolean).join(": ") || `HTTP ${tok.status}`;
    return page("Acumatica sign-in failed", `<p>The token exchange was refused (${escapeHtml(String(why))}). Ask Claude for a new connect link.</p>`, 502);
  }

  const login = await userinfoLogin(env, tok.json.access_token);
  const prev = await loadRecord(env, email);
  if (prev) await revokeQuietly(env, prev); // replacing an earlier link: do not leave its tokens live
  await saveRecord(env, email, recordFrom(tok.json, login, new Date().toISOString()));

  return page(
    "Acumatica connected",
    `<p>Your CCS sign-in <strong>${escapeHtml(email)}</strong> is now linked to Acumatica as ` +
      `<strong>${escapeHtml(login ?? "(login not reported)")}</strong>.</p>` +
      `<p>If that is not you, tell your administrator and use the <code>acumatica_disconnect</code> tool.</p>` +
      `<p>You can close this window and return to Claude.</p>`,
  );
}

async function userinfoLogin(env: Env, accessToken: string): Promise<string | undefined> {
  try {
    const r = await fetch(base(env) + USERINFO_PATH, {
      headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" }, signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (!r.ok) return undefined;
    const j = (await r.json()) as Record<string, unknown>;
    const v = j.preferred_username ?? j.name ?? j.sub;
    return typeof v === "string" ? v : undefined;
  } catch {
    return undefined;
  }
}

// ---------- tokens for tool calls ----------

/** A usable access token for this person, refreshing first if it is about to expire. */
export async function accessTokenFor(env: Env, email: string, forceRefresh = false): Promise<{ token: string; login?: string }> {
  requireOAuthConfig(env);
  const rec = await loadRecord(env, email);
  if (!rec) throw await notConnected(env, email, "You have not connected your Acumatica account yet.");
  const now = Math.floor(Date.now() / 1000);
  if (!forceRefresh && rec.expires_at - REFRESH_SKEW_S > now) return { token: rec.access_token, login: rec.acumatica_login };
  return refresh(env, email, rec);
}

async function refresh(env: Env, email: string, rec: TokenRecord): Promise<{ token: string; login?: string }> {
  if (!rec.refresh_token) {
    await deleteRecord(env, email);
    throw await notConnected(env, email, "Your Acumatica session has expired.");
  }
  const r = await postForm(env, TOKEN_PATH, {
    grant_type: "refresh_token", refresh_token: rec.refresh_token,
    client_id: env.ACUMATICA_OAUTH_CLIENT_ID!, client_secret: env.ACUMATICA_OAUTH_CLIENT_SECRET!,
  });
  if (r.ok && typeof r.json.access_token === "string") {
    // The refresh token ROTATES (verified): store the new one or the next refresh fails.
    const next = recordFrom(r.json, rec.acumatica_login, rec.linked_at, rec.refresh_token);
    await saveRecord(env, email, next);
    return { token: next.access_token, login: next.acumatica_login };
  }
  if (r.json.error === "invalid_grant") {
    // Another request may have just refreshed and stored a newer token: check once before giving up.
    const latest = await loadRecord(env, email);
    const now = Math.floor(Date.now() / 1000);
    if (latest && latest.refresh_token !== rec.refresh_token && latest.expires_at - REFRESH_SKEW_S > now) {
      return { token: latest.access_token, login: latest.acumatica_login };
    }
    await deleteRecord(env, email);
    throw await notConnected(env, email, "Your Acumatica access has expired or was revoked.");
  }
  throw new Error(`Acumatica token refresh -> ${r.status}: ${[r.json.error, r.json.error_description].filter(Boolean).join(": ") || "no detail"}`);
}

// ---------- status and disconnect ----------

export async function connectionStatus(env: Env, email: string): Promise<Record<string, unknown>> {
  requireOAuthConfig(env);
  const rec = await loadRecord(env, email);
  if (!rec) {
    return { connected: false, connect_link: await connectLink(env, email), note: "Open the link and sign in as yourself (single use, 10 minutes)." };
  }
  let token: string;
  try {
    ({ token } = await accessTokenFor(env, email));
  } catch (e) {
    return { connected: false, note: (e as Error).message };
  }
  const login = await userinfoLogin(env, token);
  const latest = await loadRecord(env, email);
  return {
    connected: login !== undefined,
    acumatica_login: login ?? rec.acumatica_login,
    linked_at: rec.linked_at,
    access_token_expires_in_s: latest ? latest.expires_at - Math.floor(Date.now() / 1000) : null,
    check: login !== undefined ? "userinfo answered with this token" : "userinfo did not answer; the link may be broken",
  };
}

async function revokeQuietly(env: Env, rec: TokenRecord): Promise<{ refresh: number | null; access: number }> {
  // Basic auth, no token_type_hint. The refresh-token revocation is known to answer 500
  // on this instance; the caller confirms with a refresh attempt instead of trusting it.
  let refreshStatus: number | null = null;
  if (rec.refresh_token) {
    refreshStatus = (await postForm(env, REVOKE_PATH, { token: rec.refresh_token }, basicAuth(env)).catch(() => ({ status: 0 }))).status;
  }
  const accessStatus = (await postForm(env, REVOKE_PATH, { token: rec.access_token }, basicAuth(env)).catch(() => ({ status: 0 }))).status;
  return { refresh: refreshStatus, access: accessStatus };
}

export async function disconnect(env: Env, email: string): Promise<Record<string, unknown>> {
  requireOAuthConfig(env);
  const rec = await loadRecord(env, email);
  if (!rec) return { disconnected: true, note: "No Acumatica account was linked." };
  const revoked = await revokeQuietly(env, rec);
  let refreshDead: boolean | null = null;
  if (rec.refresh_token) {
    const r = await postForm(env, TOKEN_PATH, {
      grant_type: "refresh_token", refresh_token: rec.refresh_token,
      client_id: env.ACUMATICA_OAUTH_CLIENT_ID!, client_secret: env.ACUMATICA_OAUTH_CLIENT_SECRET!,
    });
    refreshDead = r.json.error === "invalid_grant";
    if (r.ok && typeof r.json.access_token === "string") {
      // It still worked: revoke what was just issued so nothing is left live.
      await revokeQuietly(env, recordFrom(r.json, rec.acumatica_login, rec.linked_at));
    }
  }
  await deleteRecord(env, email);
  return {
    disconnected: true,
    acumatica_login: rec.acumatica_login,
    revoke_status: revoked,
    refresh_token_confirmed_dead: refreshDead,
    note: refreshDead === false
      ? "The refresh token still worked after revocation; its replacement was revoked. An administrator can also use REVOKE ACCESS on SM303010."
      : "Tokens revoked and the link removed.",
  };
}
