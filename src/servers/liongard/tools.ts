/**
 * Liongard MCP tools — read-only configuration intelligence for Platinum staff.
 *
 * READ-ONLY THREE LAYERS DEEP:
 *   1. registry subset  — only read tools are registered here
 *   2. transport guard  — client.assertReadOnly() refuses PUT/DELETE outright
 *                         and allows POST only on Liongard's query-shaped
 *                         read endpoints
 *   3. credential       — the access key is minted by a reader-scoped Liongard
 *                         integration user, and Liongard keys inherit that
 *                         user's permissions
 *
 * SIZE IS THE DESIGN CONSTRAINT. Measured live on 2026-09-14: a single
 * /view dataprint runs from 11 KB (TLS/SSL) to 7 MB (Microsoft 365), whose
 * ServicePrincipals key alone is 3.8 MB. Nothing here returns a whole
 * dataprint. Techs get a section index first, then one named section under a
 * byte cap, and metrics for anything that can be expressed as a single value.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Env } from "../../types";
import { type McpProps, callerId } from "../../mcp/props";
import { liongard, assertReadOnly } from "./client";
import {
  ListEnvironmentsInput, ListInspectorsInput, ListMetricsInput, ListSystemsInput,
  MetricValuesInput, RequestInput, SystemSectionInput, SystemSectionsInput,
} from "./schemas";

function ok(payload: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }] };
}
function err(message: string) {
  return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ error: message }, null, 2) }] };
}

const READ_ONLY = { readOnlyHint: true, idempotentHint: true, openWorldHint: true };

const MAX_KB_DEFAULT = 60;
const MAX_KB_CEILING = 200;

type Dict = Record<string, unknown>;

function byteLen(o: unknown): number {
  return new TextEncoder().encode(JSON.stringify(o ?? null)).length;
}
function kb(o: unknown): number {
  return Math.round((byteLen(o) / 1024) * 10) / 10;
}
function clampKb(requested?: number): number {
  const v = requested ?? MAX_KB_DEFAULT;
  return Math.max(1, Math.min(v, MAX_KB_CEILING));
}
function contains(hay: unknown, needle?: string): boolean {
  if (!needle) return true;
  return String(hay ?? "").toLowerCase().includes(needle.toLowerCase());
}

/**
 * Trim a value to a byte cap. Arrays lose items from the end and the caller is
 * told how many. Anything else that busts the cap is refused rather than
 * silently halved, because a truncated object is a lie about the config.
 */
function capped(value: unknown, maxKb: number): Dict {
  const limit = maxKb * 1024;
  const size = byteLen(value);
  if (size <= limit) return { truncated: false, size_kb: kb(value), value };
  if (Array.isArray(value)) {
    const out: unknown[] = [];
    for (const item of value) {
      out.push(item);
      if (byteLen(out) > limit) { out.pop(); break; }
    }
    return {
      truncated: true,
      size_kb: kb(value),
      returned_items: out.length,
      total_items: value.length,
      note:
        out.length === 0
          ? `No single item fits under the ${maxKb} KB cap (the collection is ${kb(value)} KB across ${value.length} items). Raise max_kb (ceiling ${MAX_KB_CEILING}) or use a narrower endpoint or filter.`
          : `Trimmed to fit the ${maxKb} KB cap. Raise max_kb (ceiling ${MAX_KB_CEILING}) or narrow the request.`,
      value: out,
    };
  }
  return {
    truncated: true,
    size_kb: kb(value),
    value: null,
    note: `This value is ${kb(value)} KB, over the ${maxKb} KB cap, and is not an array so it cannot be trimmed item by item without misrepresenting the configuration. Raise max_kb (ceiling ${MAX_KB_CEILING}) or pick a narrower section.`,
  };
}

/** Per-key size breakdown of a dataprint container, largest first. */
function sectionIndex(container: unknown): Dict[] {
  if (!container || typeof container !== "object" || Array.isArray(container)) return [];
  return Object.entries(container as Dict)
    .map(([key, v]) => {
      const e: Dict = { section: key, size_kb: kb(v), type: Array.isArray(v) ? "list" : typeof v };
      if (Array.isArray(v)) e.items = v.length;
      else if (v && typeof v === "object") e.subkeys = Object.keys(v as Dict).length;
      return e;
    })
    .sort((a, b) => Number(b.size_kb) - Number(a.size_kb));
}

async function fetchView(env: Env, systemId: number, caller: string) {
  const path = `/api/v1/systems/${systemId}/view`;
  assertReadOnly("POST", path);
  return liongard<Dict>(env, "POST", path, {}, caller);
}

export function registerLiongardTools(server: McpServer, env: Env, props: McpProps): void {
  const caller = callerId(props);

  server.registerTool(
    "liongard_list_environments",
    {
      title: "List Liongard environments",
      description:
        "List Liongard environments, which are clients. Start here when someone names a " +
        "client and you need its environment ID for other tools.",
      inputSchema: ListEnvironmentsInput,
      annotations: READ_ONLY,
    },
    async (args) => {
      try {
        const { data } = await liongard<{ Data?: Dict[] }>(env, "GET", "/api/v2/environments/", {}, caller);
        const all = data.Data ?? [];
        const rows = all
          .filter((e) => contains(e.Name, args.name_contains))
          .slice(0, args.limit ?? 100)
          .map((e) => ({
            id: e.ID, name: e.Name, short_name: e.ShortName, status: e.Status,
            tier: e.Tier, agents_count: e.AgentsCount,
            endpoint_inspector_count: e.EndpointInspectorCount, updated_on: e.UpdatedOn,
          }));
        return ok({ total: all.length, returned: rows.length, environments: rows });
      } catch (e) { return err((e as Error).message); }
    },
  );

  server.registerTool(
    "liongard_list_inspectors",
    {
      title: "List Liongard inspectors",
      description:
        "List inspector types (Microsoft 365, Active Directory, Fortinet Fortigate, TLS/SSL, " +
        "and so on). Use this to get the exact alias string that liongard_list_systems and " +
        "liongard_list_metrics expect.",
      inputSchema: ListInspectorsInput,
      annotations: READ_ONLY,
    },
    async (args) => {
      try {
        const { data } = await liongard<Dict[]>(env, "GET", "/api/v1/inspectors/", {}, caller);
        const rows = (data ?? [])
          .filter((i) => contains(i.Name, args.name_contains) || contains(i.Alias, args.name_contains))
          .map((i) => ({
            id: i.ID, name: i.Name, alias: i.Alias, category: i.InspectorCategory,
            published_status: i.PublishedStatus,
          }));
        return ok({ total: (data ?? []).length, returned: rows.length, inspectors: rows });
      } catch (e) { return err((e as Error).message); }
    },
  );

  server.registerTool(
    "liongard_list_systems",
    {
      title: "List Liongard systems",
      description:
        "List systems, where a system is one inspector running against one environment. " +
        "This is how you find the thing to investigate: 'the Microsoft 365 system at " +
        "Braner' is one row here. Filtering is done client-side on purpose, because " +
        "Liongard's condition-based filters on this endpoint return a 500.",
      inputSchema: ListSystemsInput,
      annotations: READ_ONLY,
    },
    async (args) => {
      try {
        const { data } = await liongard<Dict[]>(env, "GET", "/api/v1/systems/", {}, caller);
        const enabledOnly = args.enabled_only ?? true;
        const limit = Math.min(args.limit ?? 50, 500);
        const filtered = (data ?? []).filter((s) => {
          const envObj = (s.Environment ?? {}) as Dict;
          const insp = (s.Inspector ?? {}) as Dict;
          if (enabledOnly && s.Enabled === false) return false;
          if (args.environment_id !== undefined && Number(envObj.ID) !== args.environment_id) return false;
          if (args.inspector_alias && String(insp.Alias ?? "").toLowerCase() !== args.inspector_alias.toLowerCase()) return false;
          if (!contains(s.Name, args.name_contains)) return false;
          return true;
        });
        const rows = filtered.slice(0, limit).map((s) => {
          const envObj = (s.Environment ?? {}) as Dict;
          const insp = (s.Inspector ?? {}) as Dict;
          return {
            id: s.ID, name: s.Name, environment_id: envObj.ID, environment: envObj.Name,
            inspector_id: insp.ID, inspector: insp.Alias ?? insp.Name,
            status: s.Status, enabled: s.Enabled, run_state: s.RunState,
            latest_inspection_date: s.LatestInspectionDate, next_scheduled_for: s.NextScheduledFor,
          };
        });
        return ok({ total_matching: filtered.length, returned: rows.length, systems: rows });
      } catch (e) { return err((e as Error).message); }
    },
  );

  server.registerTool(
    "liongard_get_system_sections",
    {
      title: "Index a system's dataprint sections",
      description:
        "ALWAYS CALL THIS BEFORE liongard_get_system_section. Returns the section names " +
        "available for one system with the size of each, and no configuration data. " +
        "Dataprints are far too large to return whole (Microsoft 365 measured at 7 MB), so " +
        "this is the map you use to pick the one section the question actually needs.",
      inputSchema: SystemSectionsInput,
      annotations: READ_ONLY,
    },
    async (args) => {
      try {
        const { data, bytes } = await fetchView(env, args.system_id, caller);
        const sys = (data.system ?? {}) as Dict;
        return ok({
          system_id: args.system_id,
          system: { name: sys.Name, status: sys.Status, latest_inspection_date: sys.LatestInspectionDate },
          dataprint_total_kb: Math.round((bytes / 1024) * 10) / 10,
          views: sectionIndex(data.views),
          raw: sectionIndex(data.raw),
          guidance:
            "Prefer 'views' sections: they are Liongard's curated extraction and are usually " +
            "one to sixty KB. 'raw' is the unprocessed dataprint and individual keys there can " +
            "run to megabytes. If the answer is a single value, liongard_get_metric_values is " +
            "cheaper than either.",
        });
      } catch (e) { return err((e as Error).message); }
    },
  );

  server.registerTool(
    "liongard_get_system_section",
    {
      title: "Read one dataprint section",
      description:
        "Return one named section of a system's dataprint, size-capped. Section names come " +
        "from liongard_get_system_sections. This is the drill-down for questions the metrics " +
        "cannot answer, for example the actual firewall policy list or the group policy detail.",
      inputSchema: SystemSectionInput,
      annotations: READ_ONLY,
    },
    async (args) => {
      try {
        const source = args.source ?? "views";
        const { data } = await fetchView(env, args.system_id, caller);
        const container = data[source];
        if (!container || typeof container !== "object") {
          return err(`System ${args.system_id} has no '${source}' container in its dataprint.`);
        }
        const dict = container as Dict;
        if (!(args.section in dict)) {
          return err(
            `Section "${args.section}" not found in ${source}. Available: ${Object.keys(dict).join(", ")}`,
          );
        }
        return ok({
          system_id: args.system_id,
          source,
          section: args.section,
          ...capped(dict[args.section], clampKb(args.max_kb)),
        });
      } catch (e) { return err((e as Error).message); }
    },
  );

  server.registerTool(
    "liongard_list_metrics",
    {
      title: "List Liongard metrics",
      description:
        "List metric definitions. A metric is a JMESPath query that extracts one value from a " +
        "dataprint, so metrics are the cheap precise surface: each evaluated value costs well " +
        "under a kilobyte. Find the metrics you want here, then evaluate them with " +
        "liongard_get_metric_values. Filter by inspector, or the list runs to roughly 2,000 rows.",
      inputSchema: ListMetricsInput,
      annotations: READ_ONLY,
    },
    async (args) => {
      try {
        const { data } = await liongard<Dict[]>(env, "GET", "/api/v1/metrics/", {}, caller);
        const limit = Math.min(args.limit ?? 100, 500);
        const filtered = (data ?? []).filter((m) => {
          const insp = (m.Inspector ?? {}) as Dict;
          if (args.inspector_id !== undefined && Number(insp.ID) !== args.inspector_id) return false;
          if (args.inspector_alias && String(insp.Alias ?? "").toLowerCase() !== args.inspector_alias.toLowerCase()) return false;
          if (!contains(m.Name, args.name_contains)) return false;
          return true;
        });
        const rows = filtered.slice(0, limit).map((m) => {
          const insp = (m.Inspector ?? {}) as Dict;
          return {
            id: m.ID, uuid: m.UUID, name: m.Name, description: m.Description,
            inspector: insp.Alias ?? insp.Name, display_enabled: m.MetricDisplay,
          };
        });
        return ok({ total_matching: filtered.length, returned: rows.length, metrics: rows });
      } catch (e) { return err((e as Error).message); }
    },
  );

  server.registerTool(
    "liongard_get_metric_values",
    {
      title: "Evaluate metrics against systems",
      description:
        "Evaluate metrics for up to ten systems against their latest successful inspection. " +
        "This is the primary investigation tool: it answers 'is MFA on', 'when does that cert " +
        "expire', 'what is the firmware version' without pulling a dataprint. Get UUIDs from " +
        "liongard_list_metrics. Response is keyed by system ID, then by metric ID.",
      inputSchema: MetricValuesInput,
      annotations: READ_ONLY,
    },
    async (args) => {
      try {
        if (args.system_ids.length === 0) return err("system_ids cannot be empty");
        if (args.system_ids.length > 10) {
          return err(`Liongard evaluates at most 10 systems per call; ${args.system_ids.length} were given.`);
        }
        if (!args.metric_uuids?.length && !args.metric_ids?.length) {
          return err("Provide metric_uuids (preferred) or metric_ids. Use liongard_list_metrics to find them.");
        }
        const path = "/api/v1/metrics/bulk";
        assertReadOnly("GET", path);
        // GET with comma-joined values, NOT POST. Verified 2026-09-14: POST
        // with a JSON body ignores the uuids filter and evaluates every metric
        // on the system (one UUID in, eight metrics back), while GET with the
        // same single UUID returns exactly that one. Chunked at 100 UUIDs per
        // call to stay inside URL length limits, since an inspector like
        // Microsoft 365 carries 263 metrics.
        const CHUNK = 100;
        const uuids = args.metric_uuids ?? [];
        const ids = args.metric_ids ?? [];
        const chunks: Array<{ uuids?: string[]; metrics?: number[] }> = [];
        for (let i = 0; i < uuids.length; i += CHUNK) chunks.push({ uuids: uuids.slice(i, i + CHUNK) });
        for (let i = 0; i < ids.length; i += CHUNK) chunks.push({ metrics: ids.slice(i, i + CHUNK) });

        const merged: Dict = {};
        for (const chunk of chunks) {
          const params: Record<string, string | number | boolean | Array<string | number> | undefined> = {
            systems: args.system_ids,
            includeNonVisible: args.include_non_visible ?? true,
          };
          if (chunk.uuids) params.uuids = chunk.uuids;
          if (chunk.metrics) params.metrics = chunk.metrics;
          const { data } = await liongard<Dict>(env, "GET", path, { params }, caller);
          for (const [sid, block] of Object.entries(data ?? {})) {
            const existing = (merged[sid] ?? {}) as Dict;
            merged[sid] = { ...existing, ...(block as Dict) };
          }
        }
        const requested = uuids.length + ids.length;
        const returnedPerSystem: Dict = {};
        for (const [sid, block] of Object.entries(merged)) {
          returnedPerSystem[sid] = block && typeof block === "object" ? Object.keys(block as Dict).length : 0;
        }
        return ok({
          requested_metrics: requested,
          returned_metrics_per_system: returnedPerSystem,
          calls: chunks.length,
          ...capped(merged, clampKb(args.max_kb)),
        });
      } catch (e) { return err((e as Error).message); }
    },
  );

  server.registerTool(
    "liongard_request",
    {
      title: "Liongard API passthrough (read-only)",
      description:
        "Call any Liongard read endpoint the typed tools do not cover: launchpoints, agents, " +
        "detections, alerts, timeline, groups, users, environment groups, asset inventory, and " +
        "anything Liongard adds later. GET is open; POST is permitted only on Liongard's " +
        "query-shaped read endpoints. Writes, deletes, and the access-key and authentication " +
        "surfaces are refused. Array parameters must be comma-joined in one string, because " +
        "Liongard returns a generic 500 for repeated params.",
      inputSchema: RequestInput,
      annotations: READ_ONLY,
    },
    async (args) => {
      try {
        assertReadOnly(args.method, args.path);
        const { data, bytes } = await liongard<unknown>(
          env, args.method, args.path,
          { params: args.params, body: args.body },
          caller,
        );
        return ok({
          method: args.method,
          path: args.path,
          response_kb: Math.round((bytes / 1024) * 10) / 10,
          ...capped(data, clampKb(args.max_kb)),
        });
      } catch (e) { return err((e as Error).message); }
    },
  );
}

