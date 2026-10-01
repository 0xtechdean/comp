/**
 * The monthly refresh skips vendors whose domain was researched within this
 * window. 25 days keeps every vendor on a monthly cadence (1st → 1st is always
 * ≥ 28 days) while dropping vendors that were added or manually re-assessed
 * mid-month — re-researching those burned Firecrawl credits for no new data
 * (2026-10-01: the free plan ran dry and the last 4 vendors failed).
 */
export const REFRESH_SKIP_WINDOW_DAYS = 25;

/**
 * Extract domain from website URL for GlobalVendors lookup.
 * Removes www. prefix and returns just the domain (e.g., "example.com").
 */
export function extractDomain(
  website: string | null | undefined,
): string | null {
  if (!website) return null;

  const trimmed = website.trim();
  if (!trimmed) return null;

  try {
    // Add protocol if missing to make URL parsing work
    const urlString = /^https?:\/\//i.test(trimmed)
      ? trimmed
      : `https://${trimmed}`;
    const url = new URL(urlString);
    // Remove www. prefix and return just the domain
    return url.hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return null;
  }
}

/**
 * Split vendors into those due for a refresh and those skipped because their
 * domain already has an assessment newer than the skip window.
 */
export function partitionVendorsDueForRefresh<
  T extends { website: string | null },
>(params: {
  vendors: T[];
  recentlyAssessedWebsites: Array<string | null>;
}): { due: T[]; skipped: T[] } {
  const recentDomains = new Set(
    params.recentlyAssessedWebsites
      .map((w) => extractDomain(w))
      .filter((d): d is string => d !== null),
  );

  const due: T[] = [];
  const skipped: T[] = [];
  for (const vendor of params.vendors) {
    const domain = extractDomain(vendor.website);
    if (domain && recentDomains.has(domain)) skipped.push(vendor);
    else due.push(vendor);
  }
  return { due, skipped };
}
