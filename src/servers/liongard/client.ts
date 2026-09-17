/**
 * Liongard (ROAR) REST client — direct-to-service pattern.
 *
 * Why direct instead of Windmill-bridged: same rationale as
 * src/servers/radar/client.ts. Liongard already IS the API layer, and a
 * Liongard access key inherits the permissions of the Liongard user that
 * minted it, so the credential tier is enforced upstream. A Windmill hop
 * would add a second credential and a network leg without adding logic.
 *
 * Auth: X-ROAR-API-KEY = base64(accessKeyId:accessKeySecret).
 *
 * VERIFIED LIVE against us9 on 2026-09-14 (probe results in the MCP Gateway
 * book). These are not assumptions:
 *
 *  - REPEATED QUERY PARAMS RETURN 500. `?uuids=a&uuids=b` fails with a
 *    generic {"error":"Internal Server Error"}, as does bracket syntax
 *    (`uuids[]=`). Array values MUST be comma-joined into one param, or sent
 *    in a POST JSON body. This is the single biggest trap in this API and the
 *    reason buildQuery() joins arrays instead of appending.
 *  - /api/v1/metrics/bulk answers on GET (comma-joined) and POST (JSON body).
 *    We use POST: no URL length ceiling, which matters because the Microsoft
 *    365 inspector alone carries 263 metrics.
 *  - Most v1 collection routes want a trailing slash. /metrics/bulk redirects
 *    /bulk to /bulk/ by itself.
 *  - Condition-based filters on /api/v1/systems/ return 500; filter client-side.
 */

import type { Env } from "../../types";

export type LgOpts = {
  params?: Record<string, string | number | boolean | Array<string | number> | undefined>;
  body?: unknown;
};

export function roarHeaders(env: Env): Record<string, string> {
  const encoded = btoa(`${env.LIONGARD_ACCESS_KEY_ID}:${env.LIONGARD_ACCESS_KEY_SECRET}`);
  return {
    "X-ROAR-API-KEY": encoded,
    Accept: "application/json",
    "Content-Type": "application/json",
  };
}

/** Arrays are comma-joined, never repeated. See the 500 note in the header. */
export function buildQuery(params: LgOpts["params"]): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params ?? {})) {
    if (v === undefined || v === null) continue;
    sp.set(k, Array.isArray(v) ? v.join(",") : String(v));
  }
  const q = sp.toString();
  return q ? `?${q}` : "";
}

/**
 * POST routes that are READS in disguise. Liongard uses POST for several
 * query-shaped endpoints (the dataprint view, metric evaluation, the v2
 * *-query routes). Everything not on this list is refused for POST so the
 * generic passthrough cannot be talked into mutating anything.
 */
const POST_READ_ALLOWLIST: RegExp[] = [
  /^\/api\/v1\/systems\/\d+\/view\/?$/,
  /^\/api\/v1\/systems\/\d+\/\d+\/view\/?$/,
  /^\/api\/v1\/metrics\/bulk\/?$/,
  /^\/api\/v2\/metrics\/evaluate\/?$/,
  /^\/api\/v2\/metrics\/evaluate\/systems\/?$/,
  /^\/api\/v2\/dataprints\/evaluate\/\d+\/?$/,
  /^\/api\/v2\/detections\/?$/,
  /^\/api\/v2\/timelines\/query\/?$/,
  /^\/api\/v2\/view-agents\/?$/,
  /^\/api\/v2\/inventory\/identities\/query\/?$/,
  /^\/api\/v2\/inventory\/device-profiles\/query\/?$/,
  /^\/api\/v2\/environments\/\d+\/query\/?$/,
];

/**
 * Paths this server will never touch on any method.
 * access-keys and authentication are credential surfaces: the chat-safe rule
 * says a tool may only return data that is safe to persist forever in a log,
 * and key material fails that in both directions.
 */
const DENY: RegExp[] = [/\/access-keys/i, /\/authentication\//i, /\/webhooks/i];

/**
 * Paths the GENERIC PASSTHROUGH may reach. Default-deny, and deliberately
 * narrower than what the typed tools are allowed to call.
 *
 * Rationale, measured against the CCS instance (us3) on 2026-09-17:
 *   /api/v1/tasks/        23.5 MB across 4,498 records
 *   /api/v1/launchpoints/ 21.1 MB across 9,016 records
 *
 * Those are roughly 2.5x the sizes the Platinum handover recorded. A typed
 * tool's size cap trims the RESPONSE, but the Worker still has to fetch and
 * parse the whole payload first, so an unfiltered passthrough GET against
 * either endpoint is a plausible way to exhaust the isolate. The typed tools
 * never touch them; only the passthrough could, so the passthrough is where
 * the restriction belongs.
 *
 * Cost of default-deny, stated plainly: endpoints Liongard adds later are NOT
 * reachable until added here. That is the deliberate trade — a new entry is a
 * one-line change, an out-of-memory Worker in production is not.
 */
const PASSTHROUGH_ALLOWLIST: RegExp[] = [
  // Bounded collections, all measured under 100 KB.
  /^\/api\/v1\/agents\/?$/,
  /^\/api\/v1\/groups\/?$/,
  /^\/api\/v1\/users\/?$/,
  /^\/api\/v1\/environments\/?$/,
  /^\/api\/v1\/inspectors\/?$/,
  /^\/api\/v2\/environments\/?$/,
  /^\/api\/v2\/environment-groups\/?$/,
  /^\/api\/v2\/metrics\/?$/,
  // Per-resource reads: scoped to one record, so bounded by construction.
  /^\/api\/v1\/systems\/\d+(\/.*)?$/,
  /^\/api\/v1\/environments\/\d+(\/.*)?$/,
  /^\/api\/v1\/inspectors\/\d+(\/.*)?$/,
  /^\/api\/v1\/agents\/\d+(\/.*)?$/,
  /^\/api\/v2\/environments\/\d+(\/.*)?$/,
  // Query-shaped reads: bounded by the filter in the request body.
  /^\/api\/v1\/metrics\/bulk\/?$/,
  /^\/api\/v2\/metrics\/evaluate(\/.*)?$/,
  /^\/api\/v2\/dataprints\/evaluate\/\d+\/?$/,
  /^\/api\/v2\/detections\/?$/,
  /^\/api\/v2\/timelines\/query\/?$/,
  /^\/api\/v2\/inventory\/identities\/query\/?$/,
  /^\/api\/v2\/inventory\/device-profiles\/query\/?$/,
];

/**
 * Applies to the generic passthrough only. Typed tools call assertReadOnly
 * directly, because they legitimately read large collections under their own
 * size caps and filtering.
 */
export function assertPassthroughAllowed(path: string): void {
  if (PASSTHROUGH_ALLOWLIST.some((re) => re.test(path))) return;
  throw new Error(
    `Path ${path} is not available through the passthrough. The passthrough is restricted to an ` +
      `allow-list of bounded endpoints, because unbounded collection reads on this instance run to ` +
      `20 MB or more and can exhaust the Worker. Use a typed tool if one covers this data ` +
      `(systems, metrics, dataprint sections and environments all have one), or ask for the path ` +
      `to be added to the allow-list in src/servers/liongard/client.ts.`,
  );
}

export function assertReadOnly(method: string, path: string): void {
  if (DENY.some((re) => re.test(path))) {
    throw new Error(
      `Path ${path} is blocked: credential and webhook surfaces are excluded from this server by policy.`,
    );
  }
  if (method === "GET") return;
  if (method === "POST" && POST_READ_ALLOWLIST.some((re) => re.test(path))) return;
  throw new Error(
    `${method} ${path} is not permitted. This server is read-only: GET is open, and POST is allowed only on Liongard's query-shaped read endpoints.`,
  );
}

export type LgResult<T> = { data: T; bytes: number };

/**
 * Hard ceiling on any single Liongard response. See the guard in liongard()
 * for the measurements behind this number.
 */
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;

export async function liongard<T = unknown>(
  env: Env,
  method: "GET" | "POST",
  path: string,
  opts: LgOpts = {},
  caller?: string,
): Promise<LgResult<T>> {
  if (!path.startsWith("/api/")) {
    throw new Error(`Path must start with /api/ (got "${path}")`);
  }
  // Fail fast and legibly when the key pair is missing. Without this the
  // template below happily builds base64("undefined:undefined"), Liongard
  // answers 500 rather than 401 from Cloudflare egress, and the failure looks
  // like a broken API instead of unset configuration. Cost us a debugging
  // session on 2026-09-14.
  if (!env.LIONGARD_ACCESS_KEY_ID || !env.LIONGARD_ACCESS_KEY_SECRET) {
    throw new Error(
      "Liongard credentials are not configured on this Worker. Set LIONGARD_ACCESS_KEY_ID and " +
        "LIONGARD_ACCESS_KEY_SECRET via `wrangler secret put <NAME> --env staging` (omit --env for " +
        "production), run from the ccs-mcp repo root so wrangler.jsonc is picked up, then " +
        "confirm with `wrangler secret list --env staging`.",
    );
  }
  const url = `${env.LIONGARD_BASE_URL}${path}${buildQuery(opts.params)}`;
  const res = await fetch(url, {
    method,
    headers: roarHeaders(env),
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });

  // Refuse oversized payloads BEFORE reading the body into memory. Trimming
  // after the fact protects the conversation but not the isolate: the Worker
  // has already materialised the whole document by then. Measured on us3,
  // 2026-09-17: /api/v1/tasks/ is 23.5 MB and /api/v1/launchpoints/ is 21.1 MB,
  // while the largest endpoint any typed tool legitimately reads is
  // /api/v1/metrics/ at 5.7 MB. The ceiling sits above the latter with
  // headroom and well below the former.
  //
  // Caveat worth knowing: a chunked response carries no content-length, so
  // this guard cannot fire on one. It is a cheap backstop, not a proof.
  const declaredLength = Number(res.headers.get("content-length") ?? NaN);
  if (Number.isFinite(declaredLength) && declaredLength > MAX_RESPONSE_BYTES) {
    throw new Error(
      `Liongard ${method} ${path} declared ${Math.round(declaredLength / 1024 / 1024)} MB, over the ` +
        `${Math.round(MAX_RESPONSE_BYTES / 1024 / 1024)} MB ceiling, so it was refused without being read. ` +
        `Narrow the request: filter by environment or inspector, use a typed tool, or read one ` +
        `dataprint section rather than a whole collection.`,
    );
  }

  const text = await res.text();
  if (!res.ok) {
    // Only offer the array-param explanation when the request actually carried
    // a multi-value param. Attaching it to every 500 sent me chasing
    // serialization on calls that had no parameters at all.
    const sentMultiValue = Object.values(opts.params ?? {}).some(
      (v) => Array.isArray(v) || (typeof v === "string" && v.includes(",")),
    );
    const hint =
      res.status === 500 && sentMultiValue
        ? " (Liongard returns a generic 500 for malformed array params; arrays must be comma-joined, not repeated)"
        : res.status === 500
          ? " (a 500 on a parameterless Liongard call usually means the credential is missing or malformed rather than the endpoint being broken)"
          : "";
    throw new Error(
      `Liongard ${method} ${path} -> ${res.status}: ${text.slice(0, 200)}${hint} (caller: ${caller ?? "?"})`,
    );
  }
  const bytes = new TextEncoder().encode(text).length;
  let data: T;
  try {
    data = JSON.parse(text) as T;
  } catch {
    throw new Error(`Liongard ${method} ${path} returned non-JSON (${bytes} bytes)`);
  }
  return { data, bytes };
}
