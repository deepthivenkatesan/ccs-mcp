/**
 * Zod schemas for Liongard tool inputs. Same rules as Atlas/ITGlue/Ninja/Radar:
 * z.coerce.number() on numerics, .optional() on optionals.
 *
 * Liongard vocabulary used in the descriptions, so a tech's words map to tools:
 *   environment = a client/tenant
 *   system      = one inspector running against one environment
 *   inspector   = the integration type (Microsoft 365, Active Directory, ...)
 *   dataprint   = the JSON an inspection returns (the /view payload)
 *   metric      = a JMESPath query that extracts one value from a dataprint
 */

import { z } from "zod";

export const ListEnvironmentsInput = {
  name_contains: z.string().optional().describe("Case-insensitive substring match on environment name"),
  limit: z.coerce.number().int().optional().describe("Max results (default 100)"),
};

export const ListInspectorsInput = {
  name_contains: z.string().optional().describe("Case-insensitive substring match on inspector name or alias"),
};

export const ListSystemsInput = {
  environment_id: z.coerce.number().int().optional().describe("Only systems in this environment (client)"),
  inspector_alias: z.string().optional().describe("Inspector alias, e.g. 'Microsoft 365', 'Active Directory', 'TLS/SSL'"),
  name_contains: z.string().optional().describe("Case-insensitive substring match on system name"),
  enabled_only: z.boolean().optional().describe("Exclude disabled systems (default true)"),
  limit: z.coerce.number().int().optional().describe("Max results (default 50, max 500)"),
};

export const SystemSectionsInput = {
  system_id: z.coerce.number().int().describe("Liongard system ID (from liongard_list_systems)"),
};

export const SystemSectionInput = {
  system_id: z.coerce.number().int().describe("Liongard system ID"),
  section: z.string().describe("Section name exactly as returned by liongard_get_system_sections"),
  source: z.enum(["views", "raw"]).optional()
    .describe("'views' (default) is Liongard's curated extraction and is what you almost always want. 'raw' is the unprocessed dataprint and can be megabytes."),
  max_kb: z.coerce.number().int().optional()
    .describe("Response size cap in KB (default 60, ceiling 200). Arrays are trimmed item by item and the response says how many were dropped."),
};

export const ListMetricsInput = {
  inspector_alias: z.string().optional().describe("Only metrics for this inspector, e.g. 'Microsoft 365'"),
  inspector_id: z.coerce.number().int().optional().describe("Only metrics for this inspector ID"),
  name_contains: z.string().optional().describe("Case-insensitive substring match on metric name"),
  limit: z.coerce.number().int().optional().describe("Max results (default 100, max 500)"),
};

export const MetricValuesInput = {
  system_ids: z.array(z.coerce.number().int()).describe("System IDs to evaluate against. Liongard caps this at 10 per call."),
  metric_uuids: z.array(z.string()).optional().describe("Metric UUIDs from liongard_list_metrics. Prefer UUIDs over IDs: IDs vary between Liongard instances."),
  metric_ids: z.array(z.coerce.number().int()).optional().describe("Metric IDs, if you have those instead of UUIDs"),
  include_non_visible: z.boolean().optional()
    .describe("Evaluate metrics that are not toggled on for display in the Liongard UI (default true, which is what you want for investigation)"),
  max_kb: z.coerce.number().int().optional().describe("Response size cap in KB (default 60, ceiling 200)"),
};

export const RequestInput = {
  method: z.enum(["GET", "POST"]).describe("GET, or POST for Liongard's query-shaped read endpoints"),
  path: z.string().describe("API path starting with /api/, e.g. '/api/v1/launchpoints/' or '/api/v2/environment-groups'. Most v1 collection routes need a trailing slash."),
  params: z.record(z.string()).optional()
    .describe("Query parameters. Array values must be comma-joined in a single string: Liongard returns a generic 500 for repeated params."),
  body: z.record(z.any()).optional().describe("JSON body for POST"),
  max_kb: z.coerce.number().int().optional().describe("Response size cap in KB (default 60, ceiling 200)"),
};
