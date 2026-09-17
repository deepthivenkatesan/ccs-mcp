// props.ts
//
// The authenticated caller's identity, as established by the Cloudflare Access
// login and then carried on the OAuth grant. Every connector receives this, so
// a connector can log or scope by the human behind the call.

export interface AccessProps {
  email: string;
}

/**
 * The OAuth provider attaches the grant's props to the execution context
 * before invoking the api handler. Pulling it out is deliberately narrow:
 * a request without an email never reaches a connector.
 */
export function getProps(ctx: ExecutionContext): AccessProps | null {
  const props = (ctx as unknown as { props?: AccessProps }).props;
  if (!props || typeof props.email !== "string" || props.email.length === 0) {
    return null;
  }
  return props;
}

// ---------------------------------------------------------------------------
// Compatibility shims for connectors written against the Platinum gateway.
//
// Handover connectors (Liongard, and anything else sourced the same way) import
// `McpProps` and `callerId` rather than this gateway's own names. Aliasing here
// keeps that vendor code byte-identical to what was handed over, which is the
// point: their notes warn that editing it reintroduces paid-for bugs.
// ---------------------------------------------------------------------------

/** Alias of AccessProps, under the name handover connectors import. */
export type McpProps = AccessProps;

/**
 * A stable identifier for the authenticated caller, for logging and for tools
 * that annotate upstream requests. Access authenticated this; the client did
 * not assert it.
 */
export function callerId(props: McpProps): string {
  return props.email;
}
