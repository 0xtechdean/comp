/**
 * The integration slugs that produce cloud-security scans.
 *
 * Lives in its own module so both the query service and its tests read the same
 * list. A test that restates the slugs goes stale the moment a provider is
 * added — which is exactly how this fork's Railway provider slipped past the
 * query-service suite.
 */
export const CLOUD_PROVIDER_SLUGS = ['aws', 'gcp', 'azure', 'railway'] as const;

/**
 * The check id each provider's daily full scan is persisted under.
 *
 * The cloud-security scan persists exactly one run per connection under this
 * coarse, run-level checkId (`storeFindings` in cloud-security.service.ts). The
 * SAME connection also accumulates OTHER IntegrationCheckRun rows on different
 * schedules — per-task evidence checks (checkId = manifest check id, taskId set,
 * written ~06:00 UTC) and the on-connect "All Checks (Auto)" run (checkId
 * 'all'), each holding only a handful of results. The latest-run lookups MUST
 * scope to these scan runs; otherwise a later per-task run shadows the full
 * daily scan and the Cloud Tests dashboard shows a fraction of the findings
 * (CS-702).
 */
export const CLOUD_SCAN_CHECK_IDS = CLOUD_PROVIDER_SLUGS.map(
  (slug) => `${slug}-security-scan`,
);
