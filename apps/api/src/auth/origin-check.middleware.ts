import type { Request, Response, NextFunction } from 'express';
import { isTrustedOriginForRequest } from './trusted-origins';
import {
  isChromeExtensionOrigin,
  isCompExtensionOrigin,
  isCompExtensionOriginAllowedForRequest,
} from './origin-policy';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Paths exempt from Origin validation (webhooks, public endpoints).
 * These are called by external services that don't send browser Origin headers.
 */
const EXEMPT_PATH_PREFIXES = [
  '/api/auth', // better-auth handles its own CSRF
  '/v1/health', // health check
  '/api/docs', // swagger
  '/v1/trust-access', // public trust portal endpoints (no auth, no cookies)
];

/**
 * Carved back out of the exemption above.
 *
 * `/v1/trust-access` was exempted as "no auth, no cookies", which is true of
 * the visitor-facing routes but not of the admin subtree living under the same
 * prefix: approving an access request, denying one, revoking a grant and
 * resending access email are all session-authenticated mutations. A prefix
 * match handed them the exemption too, dropping exactly the CSRF check they
 * most need.
 */
const EXEMPTION_EXCLUDED_PREFIXES = ['/v1/trust-access/admin'];

function isOriginCheckExempt(path: string): boolean {
  if (EXEMPTION_EXCLUDED_PREFIXES.some((prefix) => path.startsWith(prefix))) {
    return false;
  }
  return EXEMPT_PATH_PREFIXES.some((prefix) => path.startsWith(prefix));
}

/**
 * Express middleware that validates the Origin header on state-changing requests.
 *
 * This is defense-in-depth against CSRF attacks that bypass CORS:
 * - HTML form submissions (Content-Type: application/x-www-form-urlencoded)
 *   don't trigger CORS preflight, so CORS alone doesn't block them.
 * - This middleware rejects any state-changing request whose Origin header
 *   doesn't match a trusted origin.
 *
 * API keys and service tokens (which don't come from browsers) typically
 * don't send an Origin header, so requests without an Origin are allowed
 * — they'll be authenticated by HybridAuthGuard instead.
 */
export function originCheckMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const origin = Array.isArray(req.headers.origin)
    ? req.headers.origin[0]
    : req.headers.origin;

  // Chrome extension origins are intentionally route-scoped.
  if (origin && isChromeExtensionOrigin(origin)) {
    if (
      isCompExtensionOrigin(origin) &&
      isCompExtensionOriginAllowedForRequest({
        method: req.method,
        origin,
        path: req.path,
      })
    ) {
      return next();
    }
    res.status(403).json({
      statusCode: 403,
      message: 'Forbidden',
    });
    return;
  }

  // Allow safe (read-only) methods for regular browser origins.
  if (SAFE_METHODS.has(req.method)) {
    return next();
  }

  // Allow exempt paths (webhooks, auth, etc.) for non-extension origins.
  if (isOriginCheckExempt(req.path)) {
    return next();
  }

  // No Origin header = not a browser request (API key, service token, curl, etc.)
  // These are authenticated via HybridAuthGuard, not cookies, so no CSRF risk.
  if (!origin) {
    return next();
  }

  // Validate Origin against trusted origins (includes dynamic subdomains and
  // custom trust-portal domains, the latter scoped to their own portal routes).
  isTrustedOriginForRequest({ method: req.method, origin, path: req.path })
    .then((trusted) => {
      if (trusted) {
        return next();
      }
      res.status(403).json({
        statusCode: 403,
        message: 'Forbidden',
      });
    })
    .catch(() => {
      res.status(403).json({
        statusCode: 403,
        message: 'Forbidden',
      });
    });
}
