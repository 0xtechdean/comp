import { getManifest, runAllChecks } from '@trycompai/integration-platform';
import type { SecurityFinding } from './cloud-security.service';
import {
  // Provider-agnostic flattener: RunAllChecksResult -> SecurityFinding[],
  // preserving each result's evidence (serviceId/findingKey) verbatim.
  gcpCheckResultsToFindings as checkResultsToFindings,
  toCheckCredentials,
  toCheckVariables,
} from './gcp-scan-fallback';

/**
 * Run-source tag persisted on IntegrationCheckRun.scanMode so reconciliation only
 * diffs Railway runs against other Railway runs.
 */
export const RAILWAY_SCAN_MODE = 'railway_checks';

/**
 * Scan a Railway connection by running the Railway manifest's checks against the
 * Railway GraphQL API and flattening the outcome into SecurityFindings.
 *
 * Railway is an integration-platform provider (its checks live in the manifest),
 * but it is surfaced on the Cloud Tests page like AWS/GCP/Azure, so the scan is
 * orchestrated + persisted by the cloud-security engine. Reusing `runAllChecks`
 * keeps a single source of truth for the check logic across both surfaces.
 */
export async function scanRailwaySecurityFindings(params: {
  credentials: Record<string, unknown>;
  variables: Record<string, unknown>;
  connectionId: string;
  organizationId: string;
  logger?: {
    info: (message: string, data?: Record<string, unknown>) => void;
    warn: (message: string, data?: Record<string, unknown>) => void;
    error: (message: string, data?: Record<string, unknown>) => void;
  };
}): Promise<SecurityFinding[]> {
  const manifest = getManifest('railway');
  if (!manifest) {
    throw new Error('Railway manifest not found in the integration registry');
  }

  const result = await runAllChecks({
    manifest,
    credentials: toCheckCredentials(params.credentials),
    variables: toCheckVariables(params.variables),
    connectionId: params.connectionId,
    organizationId: params.organizationId,
    logger: params.logger,
  });

  // If EVERY check errored (e.g. an invalid/expired token, so each GraphQL call
  // threw), fail the scan instead of persisting an empty run that would read as
  // "all clear". A partial failure keeps the checks that did succeed.
  const errored = result.results.filter((r) => r.status === 'error');
  if (result.results.length > 0 && errored.length === result.results.length) {
    throw new Error(errored[0].error || 'All Railway checks failed');
  }

  return checkResultsToFindings(result);
}
