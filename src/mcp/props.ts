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
