/**
 * Acumatica MCP tools: read-only data from the FOCOL / Sun Oil sandbox.
 *
 * READ-ONLY THREE LAYERS DEEP:
 *   1. registry subset  - only list/read tools are registered here
 *   2. transport guard  - client.assertReadOnly(): GET only, only the two
 *                         endpoints in client.ENDPOINTS, a plain entity name,
 *                         allow-listed query keys, User held to a field
 *                         allow-list (Password unreachable)
 *   3. credential       - the service account (SO Clerk + integration role +
 *                         branch access + Users screen SM201010). NOTE: its full
 *                         reach is not yet catalogued; Vendor (AP303000) is
 *                         known to be denied.
 *
 * Business tools read ExtendedDefault 23.200.001; user tools read
 * SysAdminTestEndpoint 23.200.001 (decision 13). The passthrough is
 * ExtendedDefault only: User is reachable solely through the two typed user
 * tools, so its shape is fixed.
 *
 * STAGING EXPOSURE, ACCEPTED BY THE OWNER 1 OCT 2026: until per-user sign-in
 * exists, the user tools run as the service account, so anyone who can reach
 * the connector sees every user's email and role assignments. Production waits
 * for per-user sign-in.
 *
 * Every call is its own login -> GET -> logout. logout_status is reported on
 * every response so a Worker-side logout failure is visible immediately.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { Env } from "../../types";
import { type McpProps, callerId } from "../../mcp/props";
import {
  withSession, flatten, assertReadOnly, NAME_RE, MAX_TOP,
  BUSINESS, ADMIN, ENDPOINTS, USER_PROFILE_FIELDS, type Query,
} from "./client";
import { ListInput, RequestInput, UserListInput, UserGetInput } from "./schemas";

function ok(payload: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(payload, null, 2) }] };
}
function err(message: string) {
  return { isError: true, content: [{ type: "text" as const, text: JSON.stringify({ error: message }, null, 2) }] };
}

const READ_ONLY = { readOnlyHint: true, idempotentHint: true, openWorldHint: true };

const MAX_KB_DEFAULT = 60;
const MAX_KB_CEILING = 200;
const TOP_DEFAULT = 20;

function byteLen(o: unknown): number {
  return new TextEncoder().encode(JSON.stringify(o ?? null)).length;
}
function kb(o: unknown): number {
  return Math.round((byteLen(o) / 1024) * 10) / 10;
}
function clampKb(requested?: number): number {
  return Math.max(1, Math.min(requested ?? MAX_KB_DEFAULT, MAX_KB_CEILING));
}

/**
 * Trim records to a byte cap and say how many were dropped. A non-array that
 * busts the cap is refused rather than halved.
 */
function capRecords(value: unknown, maxKb: number): Record<string, unknown> {
  const limit = maxKb * 1024;
  if (byteLen(value) <= limit) return { truncated: false, size_kb: kb(value), records: value };
  if (!Array.isArray(value)) {
    return {
      truncated: true, size_kb: kb(value), records: null,
      note: `This response is ${kb(value)} KB, over the ${maxKb} KB cap, and is not a list, so it cannot be trimmed without misrepresenting it. Raise max_kb (ceiling ${MAX_KB_CEILING}) or select fewer fields.`,
    };
  }
  const out: unknown[] = [];
  for (const item of value) {
    out.push(item);
    if (byteLen(out) > limit) { out.pop(); break; }
  }
  return {
    truncated: true, size_kb: kb(value), returned_records: out.length, fetched_records: value.length,
    note: out.length === 0
      ? `No single record fits under the ${maxKb} KB cap. Raise max_kb (ceiling ${MAX_KB_CEILING}) or select fewer fields.`
      : `Returned ${out.length} of ${value.length} fetched records to fit the ${maxKb} KB cap. Raise max_kb, lower top, or select fewer fields.`,
    records: out,
  };
}

function checkFields(names: string[]): void {
  const bad = names.filter((n) => !NAME_RE.test(n));
  if (bad.length) throw new Error(`Invalid field name(s): ${bad.join(", ")}. Use API field names such as CustomerID.`);
}

function clampTop(top?: number): number {
  const t = top ?? TOP_DEFAULT;
  if (!Number.isInteger(t) || t < 1 || t > MAX_TOP) throw new Error(`top must be an integer from 1 to ${MAX_TOP} (got ${top}).`);
  return t;
}

type ListTool = {
  name: string;
  title: string;
  entity: string;
  description: string;
  defaults: string[];
};

/**
 * One typed list tool per entity read successfully on 24 Sep 2026.
 * Vendor is absent on purpose: 403 on AP303000 for this service account.
 */
const LIST_TOOLS: ListTool[] = [
  {
    name: "acumatica_list_customers", title: "List Acumatica customers", entity: "Customer",
    description: "List customers (the AR side: who is billed). Returns ID, name, status, class, email, terms, currency and credit limit by default.",
    defaults: ["CustomerID", "CustomerName", "Status", "CustomerClass", "Email", "Terms", "CurrencyID", "CreditLimit", "LastModifiedDateTime"],
  },
  {
    name: "acumatica_list_stock_items", title: "List Acumatica stock items", entity: "StockItem",
    description: "List stock (inventory) items. Returns inventory ID, description, status, class, type, base UOM, default price and default warehouse by default. Full stock item records are the heaviest measured (about 2.5 KB each), so keep the default field set unless you need more.",
    defaults: ["InventoryID", "Description", "ItemStatus", "ItemClass", "ItemType", "BaseUOM", "DefaultPrice", "DefaultWarehouseID", "LastModified"],
  },
  {
    name: "acumatica_list_sales_orders", title: "List Acumatica sales orders", entity: "SalesOrder",
    description: "List sales order headers. Line items are NOT available: expanding Details returns an error on this instance today.",
    // OrderType, OrderNbr, Status, OrderTotal, Description: general knowledge, not seen in probe output.
    defaults: ["OrderType", "OrderNbr", "Status", "CustomerID", "Date", "OrderTotal", "CurrencyID", "Branch", "Approved", "CreditHold", "Description"],
  },
  {
    name: "acumatica_list_sales_invoices", title: "List Acumatica sales invoices", entity: "SalesInvoice",
    description: "List AR sales invoices. Returns type, reference number, customer, dates, status, amount, balance and currency by default.",
    defaults: ["Type", "ReferenceNbr", "CustomerID", "Date", "DueDate", "Status", "Amount", "Balance", "Currency", "Description"],
  },
  {
    name: "acumatica_list_bills", title: "List Acumatica AP bills", entity: "Bill",
    description: "List AP bills (what is owed to vendors). Returns type, reference number, vendor, vendor ref, dates, status, amount, balance and currency by default. Vendor records themselves are not readable by this account.",
    defaults: ["Type", "ReferenceNbr", "Vendor", "VendorRef", "Date", "DueDate", "Status", "Amount", "Balance", "CurrencyID", "Description"],
  },
  {
    name: "acumatica_list_purchase_orders", title: "List Acumatica purchase orders", entity: "PurchaseOrder",
    description: "List purchase order headers. Slow: about 4 seconds for 5 records in testing, against well under 1 second for other entities.",
    defaults: ["Type", "OrderNbr", "VendorID", "Date", "PromisedOn", "Status", "OrderTotal", "CurrencyID", "Description"],
  },
];

const LIST_SUFFIX =
  " Records come back in Acumatica's default order. No filtering yet: $filter is not verified on the " +
  "ExtendedDefault endpoint. For other entities or query options, use acumatica_request.";

/** Default fields for acumatica_list_users: identity and status, no settings flags. */
const USER_LIST_DEFAULTS = ["Login", "FirstName", "LastName", "Email", "Status", "UserType", "GuestAccount"];

export function registerAcumaticaTools(server: McpServer, env: Env, props: McpProps): void {
  const caller = callerId(props);

  for (const t of LIST_TOOLS) {
    server.registerTool(
      t.name,
      {
        title: t.title,
        description: t.description + LIST_SUFFIX,
        inputSchema: ListInput,
        annotations: READ_ONLY,
      },
      async (args) => {
        try {
          const top = clampTop(args.top);
          const select = args.all_fields ? undefined : (args.fields?.length ? args.fields : t.defaults);
          if (select) checkFields(select);
          const query: Query = { $top: String(top) };
          if (select) query.$select = select.join(",");
          // Refuse BEFORE logging in: a refused request must not cost a trial slot.
          assertReadOnly("GET", BUSINESS, t.entity, query);

          const { result, logout_status } = await withSession(env, caller, (get) => get<unknown[]>(BUSINESS, t.entity, query));
          const records = flatten(result.data);
          const fetched = Array.isArray(records) ? records.length : 0;
          return ok({
            entity: t.entity,
            requested_top: top,
            fetched,
            possibly_more: fetched === top,
            fields: select ?? "all",
            upstream_kb: Math.round((result.bytes / 1024) * 10) / 10,
            logout_status,
            ...capRecords(records, clampKb(args.max_kb)),
          });
        } catch (e) {
          return err((e as Error).message);
        }
      },
    );
  }

  server.registerTool(
    "acumatica_request",
    {
      title: "Acumatica read-only request",
      description:
        `Read-only GET against any entity on Acumatica's ${BUSINESS} ${ENDPOINTS[BUSINESS].version} endpoint, for anything the ` +
        "typed list tools do not cover. Always pass select: full records are 1 to 2.5 KB each. " +
        "Known limits on this instance: Vendor is denied (insufficient rights on AP303000); expand=Details " +
        "on SalesOrder returns a 500; filter and skip are not yet verified on this endpoint, so check that results " +
        "actually match what was asked. For users and roles, use acumatica_list_users and acumatica_get_user.",
      inputSchema: RequestInput,
      annotations: READ_ONLY,
    },
    async (args) => {
      try {
        if (args.select) checkFields(args.select.split(",").map((s) => s.trim()).filter(Boolean));
        const query: Query = { $top: String(args.top) };
        if (args.select) query.$select = args.select.split(",").map((s) => s.trim()).filter(Boolean).join(",");
        if (args.filter) query.$filter = args.filter;
        if (args.expand) query.$expand = args.expand;
        if (args.skip !== undefined) query.$skip = String(args.skip);
        // Refuse BEFORE logging in: a refused request must not cost a trial slot.
        assertReadOnly("GET", BUSINESS, args.entity, query);

        const { result, logout_status } = await withSession(env, caller, (get) => get(BUSINESS, args.entity, query));
        const records = args.raw ? result.data : flatten(result.data);
        const fetched = Array.isArray(records) ? records.length : null;
        return ok({
          entity: args.entity,
          query,
          fetched,
          possibly_more: fetched === args.top,
          ...(args.filter ? { filter_verified: false, filter_note: "$filter is not yet verified on ExtendedDefault: confirm the records match." } : {}),
          upstream_kb: Math.round((result.bytes / 1024) * 10) / 10,
          logout_status,
          ...capRecords(records, clampKb(args.max_kb)),
        });
      } catch (e) {
        return err((e as Error).message);
      }
    },
  );

  server.registerTool(
    "acumatica_list_users",
    {
      title: "List Acumatica users",
      description:
        "List Acumatica user accounts: login, first and last name, email, status, user type and guest flag by default. " +
        "Roles are NOT included, because Acumatica cannot return roles for a list of users: call acumatica_get_user " +
        "with a login for one user's assigned roles. Password is never returned. Records come back in Acumatica's " +
        "default order; the sandbox has at least 100 users, so possibly_more will often be true.",
      inputSchema: UserListInput,
      annotations: READ_ONLY,
    },
    async (args) => {
      try {
        const top = clampTop(args.top);
        const select = args.fields?.length ? args.fields : USER_LIST_DEFAULTS;
        checkFields(select);
        const query: Query = { $top: String(top), $select: select.join(",") };
        // Refuse BEFORE logging in. The guard holds User to its field allow-list.
        assertReadOnly("GET", ADMIN, "User", query);

        const { result, logout_status } = await withSession(env, caller, (get) => get<unknown[]>(ADMIN, "User", query));
        const records = flatten(result.data);
        const fetched = Array.isArray(records) ? records.length : 0;
        return ok({
          entity: "User",
          endpoint: ADMIN,
          requested_top: top,
          fetched,
          possibly_more: fetched === top,
          fields: select,
          upstream_kb: Math.round((result.bytes / 1024) * 10) / 10,
          logout_status,
          ...capRecords(records, clampKb(args.max_kb)),
        });
      } catch (e) {
        return err((e as Error).message);
      }
    },
  );

  server.registerTool(
    "acumatica_get_user",
    {
      title: "Get an Acumatica user and their roles",
      description:
        "One Acumatica user's profile and the roles assigned to them, by login. Returns only assigned roles " +
        "(role name and description): Acumatica returns every role in the system with a Selected flag, so " +
        "unassigned rows are dropped and counted. Password is never returned. Use acumatica_list_users to find a login.",
      inputSchema: UserGetInput,
      annotations: READ_ONLY,
    },
    async (args) => {
      try {
        const login = args.login.trim();
        const query: Query = { $expand: "Roles", $select: [...USER_PROFILE_FIELDS, "Roles"].join(",") };
        // Refuse BEFORE logging in: bad logins and disallowed shapes never reach Acumatica.
        assertReadOnly("GET", ADMIN, "User", query, login);

        const { result, logout_status } = await withSession(env, caller, (get) => get(ADMIN, "User", query, login));
        const record = flatten(result.data);
        if (!record || typeof record !== "object" || Array.isArray(record)) {
          throw new Error(`Acumatica returned an unexpected shape for user ${login}: expected one record.`);
        }
        const { Roles, ...profile } = record as Record<string, unknown>;
        if (!Array.isArray(Roles)) {
          throw new Error(
            `Acumatica returned user ${login} without a Roles detail, so assigned roles cannot be shown. ` +
              "This is the silent-omission behaviour recorded on the wiki; tell the connector owner.",
          );
        }
        const assigned = Roles
          .filter((r) => (r as Record<string, unknown>)?.Selected === true)
          .map((r) => {
            const o = r as Record<string, unknown>;
            return { RoleName: o.RoleName, RoleDescription: o.RoleDescription };
          });
        const capped = capRecords(assigned, clampKb(args.max_kb));
        return ok({
          entity: "User",
          endpoint: ADMIN,
          login,
          upstream_kb: Math.round((result.bytes / 1024) * 10) / 10,
          logout_status,
          role_rows_total: Roles.length,
          roles_assigned: assigned.length,
          profile,
          roles: capped.records,
          roles_truncated: capped.truncated,
          ...(capped.note ? { roles_note: capped.note } : {}),
        });
      } catch (e) {
        return err((e as Error).message);
      }
    },
  );
}
