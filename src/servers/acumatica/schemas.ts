/**
 * Zod schemas for Acumatica tool inputs. Same rules as Liongard:
 * z.coerce.number() on numerics, .optional() on optionals.
 *
 * Acumatica vocabulary used in descriptions so a tech's words map to tools:
 *   entity   = a contract-API object (Customer, SalesOrder, Bill, ...)
 *   field    = a property of an entity, as named in the API (CustomerID)
 *   endpoint = ExtendedDefault 23.200.001, the only one this server reads
 */

import { z } from "zod";

const top = z.coerce.number().int().optional()
  .describe("How many records to return (default 20, max 100). Records come back in Acumatica's default order.");
const fields = z.array(z.string()).optional()
  .describe("Field names to return, exactly as the API names them (e.g. CustomerID). Omit for this tool's default set. Unknown names may make Acumatica return an error.");
const allFields = z.boolean().optional()
  .describe("Return every field instead of the default set. Records are 1 to 2.5 KB each unselected, so this fills the size cap quickly.");
const maxKb = z.coerce.number().int().optional()
  .describe("Response size cap in KB (default 60, ceiling 200). Records are trimmed one by one and the response says how many were dropped.");

export const ListInput = { top, fields, all_fields: allFields, max_kb: maxKb };

export const RequestInput = {
  entity: z.string()
    .describe("Entity name under ExtendedDefault 23.200.001, e.g. 'Customer', 'StockItem', 'SalesOrder'. A single name only: no keys, slashes or actions."),
  top: z.coerce.number().int()
    .describe("Required. Records to return, 1 to 100."),
  select: z.string().optional()
    .describe("Comma-separated field names ($select). Strongly recommended: it cut Customer by 79% in testing."),
  filter: z.string().optional()
    .describe("OData $filter, e.g. \"Status eq 'Active'\". NOT YET VERIFIED to filter on this instance: check the results actually match."),
  expand: z.string().optional()
    .describe("OData $expand. Known to fail: 'Details' on SalesOrder returns a 500 today."),
  skip: z.coerce.number().int().optional()
    .describe("OData $skip for paging. Not yet verified on this instance."),
  raw: z.boolean().optional()
    .describe("Return Acumatica's {\"value\": ...} wrapping as-is instead of plain values (default false)."),
  max_kb: maxKb,
};
