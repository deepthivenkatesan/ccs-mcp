# ccs-mcp

The CCS MCP Gateway: one Cloudflare Worker hosting many MCP connectors, one per
URL path. Full background is in the wiki, book **MCP Platform**.

## Layout

```
src/
  index.ts              OAuth, routing, and the registry
  types.ts              the Env interface: every var and secret
  verifyIdToken.ts      Access id_token verification
  mcp/
    props.ts            the authenticated caller's identity
    transport.ts        MCP over Streamable HTTP (stateless)
  servers/
    selftest/server.ts  no-vendor health connector
wrangler.jsonc
```

Adding a connector is a directory under `servers/` plus one line in `REGISTRY`
in `index.ts`.

## Branches and environments

| Branch | Worker | URL |
|---|---|---|
| `stage` | `ccs-mcp-stage` | https://ccs-mcp-stage.ccstech.workers.dev |
| `main` | `ccs-mcp` | https://ccs-mcp.ccstech.workers.dev |

A deploy target is a single slot: deploying replaces what is live entirely.
Merge into `stage` and let that deploy. Never deploy a feature branch to a
shared environment.

**`main` is protected by convention, not by GitHub.** Branch protection is not
enforced on private repos under a personal account, so rulesets here save but
stay inactive. Work on `stage`; Matt does the `main` merges.

## Deploying

Must run from inside CT 126 — the Cloudflare account API token is IP-restricted
to the platform network. From the Proxmox host:

```
set -a; source /root/.ccs-creds/cloudflare; set +a
pct exec 126 -- env CLOUDFLARE_API_TOKEN="$token" CLOUDFLARE_ACCOUNT_ID="$account_id" \
  bash -lc "cd /opt/ccs-mcp && npx wrangler deploy --env staging"
```

Omitting `--env staging` targets production.

## Secrets

`ACCESS_OIDC_CLIENT_SECRET` is the only secret. Everything else is a plain var
in `wrangler.jsonc`.

```
npx wrangler secret put ACCESS_OIDC_CLIENT_SECRET --env staging   # staging
npx wrangler secret put ACCESS_OIDC_CLIENT_SECRET                 # production
```

## Verifying

1. `GET /status` — Worker up, registry loaded, and which slot answered.
2. `POST /<connector>` unauthenticated — must return **401**.
3. `tools/list` over a real session via `npx -y mcp-remote <url>/<connector>`.
4. Only then add it as a custom connector in Claude. Leave the OAuth client
   fields blank; the gateway supports dynamic client registration.
