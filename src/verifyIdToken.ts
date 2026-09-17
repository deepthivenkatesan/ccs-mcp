// verifyIdToken.ts
//
// Verifies an OIDC id_token issued by the Cloudflare Access "CCS MCP Gateway"
// SaaS OIDC app. Deliberately mirrors the pattern @cloudflare/workers-oauth-provider
// uses internally for its own JWT verification (ID-JAG), reusing its exported
// low-level helpers rather than pulling in a separate JOSE library.

import {
  base64UrlToBytes,
  parseJwtJsonPart,
  getJwtCryptoAlgorithms,
} from "@cloudflare/workers-oauth-provider";

export interface AccessIdTokenClaims {
  iss: string;
  aud: string | string[];
  sub: string;
  exp: number;
  iat: number;
  email?: string;
  [claim: string]: unknown;
}

interface Jwk {
  kid?: string;
  kty: string;
  alg?: string;
  use?: string;
  key_ops?: string[];
  [k: string]: unknown;
}

interface Jwks {
  keys: Jwk[];
}

const jwksCache = new Map<string, { fetchedAt: number; jwks: Jwks }>();
const JWKS_CACHE_TTL_MS = 5 * 60 * 1000;

async function fetchJwks(jwksUrl: string): Promise<Jwks> {
  const cached = jwksCache.get(jwksUrl);
  if (cached && Date.now() - cached.fetchedAt < JWKS_CACHE_TTL_MS) {
    return cached.jwks;
  }
  const res = await fetch(jwksUrl);
  if (!res.ok) {
    throw new Error(`Failed to fetch JWKS from ${jwksUrl}: HTTP ${res.status}`);
  }
  const jwks = (await res.json()) as Jwks;
  jwksCache.set(jwksUrl, { fetchedAt: Date.now(), jwks });
  return jwks;
}

function selectJwk(jwks: Jwks, alg: string, kid?: string): Jwk {
  const matching = (jwks.keys ?? []).filter((key) => {
    if (kid && key.kid !== kid) return false;
    if (key.alg && key.alg !== alg) return false;
    if (key.use && key.use !== "sig") return false;
    if (Array.isArray(key.key_ops) && !key.key_ops.includes("verify")) return false;
    if (alg.startsWith("RS") && key.kty !== "RSA") return false;
    if (alg.startsWith("ES") && key.kty !== "EC") return false;
    return true;
  });
  const picked = kid ? matching[0] : matching.length === 1 ? matching[0] : undefined;
  if (!picked) {
    throw new Error(`No matching JWKS key found (kid=${kid ?? "none"}, alg=${alg})`);
  }
  return picked;
}

/**
 * Verifies a compact JWS id_token: signature, issuer, audience, and expiry.
 * Throws on any failure. Returns the decoded claims on success.
 */
export async function verifyAccessIdToken(
  idToken: string,
  opts: { jwksUrl: string; expectedIssuer: string; expectedAudience: string }
): Promise<AccessIdTokenClaims> {
  const parts = idToken.split(".");
  if (parts.length !== 3 || parts.some((p) => p.length === 0)) {
    throw new Error("Malformed id_token");
  }
  const [encodedHeader, encodedClaims, encodedSignature] = parts;

  const header = parseJwtJsonPart(encodedHeader) as { alg?: string; kid?: string; typ?: string };
  const claims = parseJwtJsonPart(encodedClaims) as unknown as AccessIdTokenClaims;
  const signature = base64UrlToBytes(encodedSignature);
  const signingInput = new TextEncoder().encode(`${encodedHeader}.${encodedClaims}`);

  const alg = header.alg;
  if (!alg || alg === "none") {
    throw new Error(`Unsupported id_token alg: ${String(alg)}`);
  }

  const jwks = await fetchJwks(opts.jwksUrl);
  const jwk = selectJwk(jwks, alg, header.kid);

  const { importAlgorithm, verifyAlgorithm } = getJwtCryptoAlgorithms(alg);
  const key = await crypto.subtle.importKey("jwk", jwk as JsonWebKey, importAlgorithm, false, ["verify"]);
  const valid = await crypto.subtle.verify(verifyAlgorithm, key, signature, signingInput);
  if (!valid) {
    throw new Error("id_token signature verification failed");
  }

  const now = Math.floor(Date.now() / 1000);
  const skewSeconds = 60;
  if (typeof claims.exp !== "number" || claims.exp + skewSeconds < now) {
    throw new Error("id_token is expired");
  }
  if (typeof claims.iat === "number" && claims.iat - skewSeconds > now) {
    throw new Error("id_token iat is in the future");
  }
  if (claims.iss !== opts.expectedIssuer) {
    throw new Error(`id_token issuer mismatch: expected ${opts.expectedIssuer}, got ${claims.iss}`);
  }
  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(opts.expectedAudience)) {
    throw new Error(`id_token audience mismatch: expected ${opts.expectedAudience}, got ${JSON.stringify(claims.aud)}`);
  }

  return claims;
}
