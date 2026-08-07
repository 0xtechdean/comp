/**
 * What a custom trust-portal domain is allowed to reach.
 *
 * A customer can point any domain they like at their trust portal, and once the
 * portal is published that domain is reflected in `Access-Control-Allow-Origin`
 * with credentials enabled, and passes the CSRF origin check on unsafe methods.
 * Previously that was all-or-nothing: an origin admitted for a trust portal
 * could address every endpoint in the API.
 *
 * Nothing was directly exploitable — session cookies are SameSite=Lax, so a
 * cross-site request from a custom domain carries no session — but it left a
 * customer-controlled origin one cookie-policy change away from reading
 * authenticated responses. These rules cut the reachable surface down to the
 * portal's own visitor-facing routes.
 *
 * Deliberately kept free of I/O so the policy can be tested exhaustively; the
 * domain -> portal lookup lives in auth.server.ts.
 */

const TRUST_PORTAL_PREFIX = '/v1/trust-access';

/**
 * The admin half of the same controller — listing access requests, approving
 * them, revoking grants. It is called from app.trycomp.ai and guarded by
 * HybridAuthGuard, never reached from a portal visitor's browser.
 */
const TRUST_PORTAL_ADMIN_PREFIX = '/v1/trust-access/admin';

/**
 * Route families keyed by an opaque per-grant token rather than by the portal's
 * slug. The token IS the authorization: it is unguessable and is issued to one
 * named visitor, so it cannot be derived from whichever origin is asking. There
 * is no slug in these paths to scope against.
 */
const TOKEN_SCOPED_SEGMENTS = new Set(['access', 'nda']);

function normalizePath(path: string): string {
  if (path.length <= 1) return path;
  return path.replace(/\/+$/, '');
}

/**
 * The path segment straight after `/v1/trust-access/`, or null when the request
 * targets the collection root.
 */
function firstSegmentAfterPrefix(path: string): string | null {
  const rest = path.slice(TRUST_PORTAL_PREFIX.length + 1);
  if (!rest) return null;
  const [segment] = rest.split('/');
  return segment || null;
}

export function isTrustPortalPath(path: string): boolean {
  const normalized = normalizePath(path);
  return (
    normalized === TRUST_PORTAL_PREFIX ||
    normalized.startsWith(`${TRUST_PORTAL_PREFIX}/`)
  );
}

/**
 * Whether a request from a custom trust-portal domain may proceed.
 *
 * @param slug the friendlyUrl of the portal that owns the requesting domain, or
 *   null when that portal has no slug — in which case only the token-scoped
 *   routes remain reachable, which is the safe reading.
 */
export function isTrustPortalRequestAllowed(params: {
  path: string;
  slug: string | null;
}): boolean {
  const path = normalizePath(params.path);

  if (!isTrustPortalPath(path)) return false;
  if (
    path === TRUST_PORTAL_ADMIN_PREFIX ||
    path.startsWith(`${TRUST_PORTAL_ADMIN_PREFIX}/`)
  ) {
    return false;
  }

  const segment = firstSegmentAfterPrefix(path);
  if (!segment) return false;
  if (TOKEN_SCOPED_SEGMENTS.has(segment)) return true;

  // Everything else is /v1/trust-access/:friendlyUrl/... — a portal may only
  // address its own slug, so one customer's domain cannot read another's
  // portal through this allowance.
  return params.slug !== null && segment === params.slug;
}
