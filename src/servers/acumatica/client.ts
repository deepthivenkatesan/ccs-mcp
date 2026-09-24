/**
 * Acumatica contract-based REST client, direct-to-service pattern.
 *
 * Instance: FOCOL / Sun Oil sandbox. Endpoint ExtendedDefault 23.200.001,
 * confirmed on SM207060. Probe results and error vocabulary: MCP Platform
 * book, page "Acumatica (in progress)".
 *
 * Auth is a COOKIE SESSION: POST /entity/auth/login {name,password,tenant},
 * then send the returned cookies, then POST /entity/auth/logout. The sandbox
 * is in trial mode with TWO concurrent users, so an orphaned session can lock
 * real people out. Every call therefore runs inside withSession(), which logs
 * out in `finally` on every path. Concurrency across parallel calls is NOT
 * handled (deferred by the owner, 24 Sep 2026).
 *
 * VERIFIED LIVE on 2026-09-24, not assumptions:
 *  - Logout MUST carry Content-Length: 0. Without it IIS answers 411 and the
 *    session is NOT ended. A non-2xx logout is surfaced as an error here.
 *  - 403 body: {"message":"You have insufficient rights to access the
 *    <Entity> (<ScreenID>) form."}. Vendor (AP303000) is denied today.
 *  - 500 bodies carry message, exceptionMessage AND a full server stack
 *    trace. Only message and exceptionMessage are surfaced.
 *  - $select narrows the payload (Customer: 79% smaller). $filter returned
 *    200 but is NOT verified to filter. $expand=Details on SalesOrder -> 500.
 *  - Query keys are sent with a literal "$" and commas unencoded, exactly as
 *    probed. URLSearchParams would send %24top, which was never tested.
 */

import type { Env } from "../../types";

export const ENDPOINT = "ExtendedDefault";
export const VERSION = "23.200.001";
const PREFIX = `/entity/${ENDPOINT}/${VERSION}/`;

/** Hard ceiling on one response, refused before the body is read. */
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
/** Per-GET timeout. The SDK bridge gives a whole request 25 s. */
const GET_TIMEOUT_MS = 20_000;
/** Largest $top any caller may ask for. */
export const MAX_TOP = 100;

/** Entity names and field names: letters, digits, underscore. Nothing else. */
export const NAME_RE = /^[A-Za-z][A-Za-z0-9_]*$/;
const ALLOWED_QUERY_KEYS = new Set(["$top", "$select", "$filter", "$expand", "$skip"]);

export type Query = Partial<Record<"$top" | "$select" | "$filter" | "$expand" | "$skip", string>>;

/**
 * Transport guard. GET only, only under the one endpoint/version, only a plain
 * entity name after it. The auth routes are reachable solely from
 * withSession() below, never through a tool.
 */
export function assertReadOnly(method: string, entity: string, query: Query): void {
  if (method !== "GET") {
    throw new Error(`${method} is not permitted. This server is read-only: GET only.`);
  }
  if (!NAME_RE.test(entity)) {
    throw new Error(
      `"${entity}" is not a plain entity name. Only a single entity name (letters, digits, underscore) ` +
        `under ${ENDPOINT} ${VERSION} can be read, e.g. "Customer".`,
    );
  }
  if (/^auth$/i.test(entity)) {
    throw new Error("The auth routes are excluded from this server by policy.");
  }
  for (const k of Object.keys(query)) {
    if (!ALLOWED_QUERY_KEYS.has(k)) {
      throw new Error(`Query option ${k} is not permitted. Allowed: ${[...ALLOWED_QUERY_KEYS].join(", ")}.`);
    }
  }
  const top = Number(query.$top);
  if (!Number.isInteger(top) || top < 1 || top > MAX_TOP) {
    throw new Error(`$top is required and must be an integer from 1 to ${MAX_TOP} (got "${query.$top ?? ""}").`);
  }
}

/** Encode a value as the probe sent it: spaces as %20, commas left as commas. */
function enc(v: string): string {
  return encodeURIComponent(v).replace(/%2C/gi, ",");
}

export function buildQuery(query: Query): string {
  const parts = Object.entries(query)
    .filter(([, v]) => v !== undefined && v !== "")
    .map(([k, v]) => `${k}=${enc(String(v))}`);
  return parts.length ? `?${parts.join("&")}` : "";
}

/** Upstream error text without the stack trace Acumatica attaches to 500s. */
function upstreamMessage(text: string): string {
  try {
    const j = JSON.parse(text) as { message?: string; exceptionMessage?: string };
    const parts = [j.message, j.exceptionMessage].filter(Boolean);
    if (parts.length) return parts.join(" | ");
  } catch {
    /* not JSON, e.g. the IIS 411 page */
  }
  return text.replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim().slice(0, 300);
}

function requireConfig(env: Env): void {
  const missing = [
    ["ACUMATICA_BASE_URL", env.ACUMATICA_BASE_URL],
    ["ACUMATICA_TENANT", env.ACUMATICA_TENANT],
    ["ACUMATICA_USERNAME", env.ACUMATICA_USERNAME],
    ["ACUMATICA_PASSWORD", env.ACUMATICA_PASSWORD],
  ].filter(([, v]) => !v).map(([n]) => n);
  if (missing.length) {
    throw new Error(
      `Acumatica is not configured on this Worker: ${missing.join(", ")} unset. ` +
        `ACUMATICA_BASE_URL and ACUMATICA_TENANT are vars in wrangler.jsonc (top level AND env.staging). ` +
        `The username and password are secrets: \`wrangler secret put <n> --env staging\` from CT 126, ` +
        `then check the untruncated \`wrangler secret list --env staging\`.`,
    );
  }
}

/** "name=value" pairs from every Set-Cookie header, joined for a Cookie header. */
function cookieHeader(res: Response): string {
  const h = res.headers as Headers & { getSetCookie?: () => string[] };
  const all = h.getSetCookie ? h.getSetCookie() : [res.headers.get("set-cookie") ?? ""];
  return all.map((c) => c.split(";")[0].trim()).filter(Boolean).join("; ");
}

export type AcuGet = <T = unknown>(entity: string, query: Query) => Promise<{ data: T; bytes: number }>;

/**
 * Log in, run fn, and ALWAYS log out. A failed logout is an error even when
 * the read succeeded, because it may leave a trial slot occupied.
 */
export async function withSession<R>(
  env: Env,
  caller: string,
  fn: (get: AcuGet) => Promise<R>,
): Promise<{ result: R; logout_status: number }> {
  requireConfig(env);
  const base = env.ACUMATICA_BASE_URL.replace(/\/+$/, "");

  const login = await fetch(`${base}/entity/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({ name: env.ACUMATICA_USERNAME, password: env.ACUMATICA_PASSWORD, tenant: env.ACUMATICA_TENANT }),
  });
  if (!login.ok) {
    const msg = upstreamMessage(await login.text());
    // The wiki's first check for a credential-looking failure is the tenant string.
    const hint = /password|credential|user|invalid|tenant|company/i.test(msg)
      ? ` Check the tenant string ("${env.ACUMATICA_TENANT}") before the credential.`
      : "";
    throw new Error(`Acumatica login -> ${login.status}: ${msg}.${hint} (caller: ${caller})`);
  }
  const cookies = cookieHeader(login);
  await login.body?.cancel();

  const get: AcuGet = async <T,>(entity: string, query: Query) => {
    assertReadOnly("GET", entity, query);
    const path = `${PREFIX}${entity}${buildQuery(query)}`;
    const res = await fetch(`${base}${path}`, {
      method: "GET",
      headers: { Cookie: cookies, Accept: "application/json" },
      signal: AbortSignal.timeout(GET_TIMEOUT_MS),
    });
    const declared = Number(res.headers.get("content-length") ?? NaN);
    if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
      await res.body?.cancel();
      throw new Error(
        `Acumatica GET ${entity} declared ${Math.round(declared / 1024)} KB, over the ` +
          `${MAX_RESPONSE_BYTES / 1024 / 1024} MB ceiling, so it was refused without being read. Lower top or use select.`,
      );
    }
    const text = await res.text();
    if (!res.ok) throw new Error(`Acumatica GET ${entity} -> ${res.status}: ${upstreamMessage(text)}`);
    const bytes = new TextEncoder().encode(text).length;
    try {
      return { data: JSON.parse(text) as T, bytes };
    } catch {
      throw new Error(`Acumatica GET ${entity} returned non-JSON (${bytes} bytes)`);
    }
  };

  let result: R | undefined;
  let readError: unknown;
  try {
    result = await fn(get);
  } catch (e) {
    readError = e;
  }

  // Logout on every path. An explicit empty body makes the runtime send
  // Content-Length: 0; without one IIS answers 411 and the session survives.
  // Verified with curl (-H "Content-Length: 0"); the Worker's equivalent is
  // verified on staging by the logout_status every tool reports.
  let logoutStatus = 0;
  let logoutMsg = "";
  try {
    const out = await fetch(`${base}/entity/auth/logout`, {
      method: "POST",
      headers: { Cookie: cookies },
      body: "",
    });
    logoutStatus = out.status;
    logoutMsg = out.ok ? "" : upstreamMessage(await out.text());
    if (out.ok) await out.body?.cancel();
  } catch (e) {
    logoutMsg = `network error: ${(e as Error).message}`;
  }

  if (logoutStatus < 200 || logoutStatus > 299) {
    const prior = readError ? `The read also failed: ${(readError as Error).message}. ` : "";
    throw new Error(
      `${prior}Acumatica logout -> ${logoutStatus || "no response"}: ${logoutMsg}. The session may still hold ` +
        `one of the sandbox's two trial slots; tell the connector owner. (caller: ${caller})`,
    );
  }
  if (readError) throw readError;
  return { result: result as R, logout_status: logoutStatus };
}

/**
 * Acumatica wraps every field as {"value": x}; empty fields are {}. Unwrap to
 * plain values, drop empties, and drop _links/rowNumber plus custom/note when
 * empty. Nested arrays and objects are unwrapped recursively.
 */
export function flatten(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(flatten);
  if (!v || typeof v !== "object") return v;
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o);
  if (keys.length === 1 && keys[0] === "value") return o.value;
  const out: Record<string, unknown> = {};
  for (const [k, raw] of Object.entries(o)) {
    if (k === "_links" || k === "rowNumber") continue;
    const f = flatten(raw);
    if (f === undefined || f === null || f === "") continue;
    if (typeof f === "object" && !Array.isArray(f) && Object.keys(f as object).length === 0) continue;
    out[k] = f;
  }
  return out;
}
