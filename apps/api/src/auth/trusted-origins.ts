import { db } from '@db';
import { Redis } from '@upstash/redis';
import { isStaticTrustedOrigin, isStaticTrustedOriginForRequest } from './origin-policy';
import { isTrustPortalRequestAllowed } from './trust-portal-origin-policy';

/**
 * Which browser origins may talk to this API.
 *
 * Extracted from auth.server.ts so the CORS and CSRF middlewares stop importing
 * the whole better-auth server — and its ESM-only dependency tree — just to
 * check an origin, which also makes this logic directly testable.
 */

// v2: the cached value gained the portal slug, so it must not be read back
// through the key that still holds v1's bare string[] entries.
const CORS_DOMAINS_CACHE_KEY = 'cors:custom-domains:v2';
const CORS_DOMAINS_CACHE_TTL_SECONDS = 5 * 60; // 5 minutes

/** A published portal's domain and the slug its own routes are keyed by. */
type CachedCustomDomain = { domain: string; slug: string | null };

// Optional: only construct the Redis client when Upstash is configured.
// Without it, custom-domain CORS lookups fall back to the DB directly and the
// API still boots (self-hosting doesn't require Upstash).
const corsRedisClient =
  process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN
    ? new Redis({
        url: process.env.UPSTASH_REDIS_REST_URL,
        token: process.env.UPSTASH_REDIS_REST_TOKEN,
      })
    : null;

/**
 * Published custom trust-portal domains, for the CORS allowlist.
 *
 * Deliberately does NOT require the DNS-verification flag — see PR #2371. That
 * flag only flips once an admin finishes our DNS check, but Vercel serves the
 * portal as soon as the domain is attached, so requiring it made every
 * client-side call from a live portal fail CORS ("Request Access" →
 * "Failed to fetch"). It regressed once as a one-line change in c21c6565d and
 * went unnoticed for months. auth-server-origins.spec.ts guards the function
 * body, so keep this explanation out here where it cannot trip the check.
 */
async function getCustomDomains(): Promise<Map<string, string | null>> {
  // Try Redis cache first (non-fatal if Redis is unavailable)
  try {
    const cached =
      await corsRedisClient?.get<CachedCustomDomain[]>(CORS_DOMAINS_CACHE_KEY);
    if (cached) {
      return new Map(cached.map((entry) => [entry.domain, entry.slug]));
    }
  } catch (error) {
    console.error('[CORS] Redis cache read failed, falling back to DB:', error);
  }

  // Cache miss or Redis unavailable — query DB
  try {
    const trusts = await db.trust.findMany({
      where: {
        domain: { not: null },
        status: 'published',
      },
      select: { domain: true, friendlyUrl: true },
    });

    const entries: CachedCustomDomain[] = trusts
      .filter((t): t is typeof t & { domain: string } => t.domain !== null)
      .map((t) => ({ domain: t.domain, slug: t.friendlyUrl }));

    // Best-effort cache update (don't lose DB results if Redis SET fails)
    try {
      await corsRedisClient?.set(CORS_DOMAINS_CACHE_KEY, entries, {
        ex: CORS_DOMAINS_CACHE_TTL_SECONDS,
      });
    } catch {
      // Redis unavailable — continue without caching
    }

    return new Map(entries.map((entry) => [entry.domain, entry.slug]));
  } catch (error) {
    console.error('[CORS] Failed to fetch custom domains from DB:', error);
    return new Map();
  }
}

/**
 * Check if an origin is trusted. Checks (in order):
 * 1. Static trusted origins list
 * 2. *.trycomp.ai / *.trust.inc subdomains
 * 3. Published custom domains from the DB (cached in Redis, TTL 5 min)
 */
export async function isTrustedOrigin(origin: string): Promise<boolean> {
  if (isStaticTrustedOrigin(origin)) {
    return true;
  }

  // Check verified custom domains from DB via Redis cache
  try {
    const url = new URL(origin);
    const customDomains = await getCustomDomains();
    return customDomains.has(url.hostname);
  } catch {
    return false;
  }
}

/**
 * Whether an origin may make this specific request.
 *
 * Static origins (our own apps, the extension) keep their existing treatment.
 * A custom trust-portal domain is admitted only for its own portal's
 * visitor-facing routes — see trust-portal-origin-policy.ts for why, and for
 * the rules themselves.
 *
 * Used by BOTH the CORS middleware and the CSRF origin check, so a domain
 * cannot be refused the response while still being allowed to make the write.
 */
export async function isTrustedOriginForRequest(params: {
  method: string;
  origin: string;
  path: string;
}): Promise<boolean> {
  if (isStaticTrustedOriginForRequest(params)) {
    return true;
  }

  let hostname: string;
  try {
    hostname = new URL(params.origin).hostname;
  } catch {
    return false;
  }

  const customDomains = await getCustomDomains();
  if (!customDomains.has(hostname)) return false;

  const allowed = isTrustPortalRequestAllowed({
    path: params.path,
    slug: customDomains.get(hostname) ?? null,
  });

  if (!allowed) {
    // A portal reaching for something outside its own routes is either an
    // attempt or a route we failed to account for; either way it should be
    // visible rather than a silent CORS failure in someone's browser.
    console.warn(
      `[CORS] Trust-portal origin ${params.origin} denied for ${params.method} ${params.path}`,
    );
  }

  return allowed;
}
