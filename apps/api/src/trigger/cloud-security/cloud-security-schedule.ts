import { getManifest } from '@trycompai/integration-platform';
import { db } from '@db';
import { logger, schedules } from '@trigger.dev/sdk';
import { runCloudSecurityScan } from './run-cloud-security-scan';

export interface CloudSecurityOrchestrationResult {
  success: boolean;
  connectionsTriggered: number;
  totalConnections: number;
  error?: string;
}

/**
 * Enumerate every active connection whose provider is a multi-connection cloud
 * provider (AWS, Railway, …) and batch-trigger a per-connection security scan.
 *
 * Extracted from the schedule body so the same orchestration can run from either
 * the dedicated `cloudSecuritySchedule` task OR — on self-hosted, where the
 * trigger.dev free tier caps declarative schedules — folded into the daily
 * `integrationChecksSchedule`. `supportsMultipleConnections` is the manifest flag
 * that marks a provider as cloud-security-scannable.
 */
export async function orchestrateCloudSecurityScans(): Promise<CloudSecurityOrchestrationResult> {
  const allConnections = await db.integrationConnection.findMany({
    where: { status: 'active' },
    include: { provider: { select: { slug: true, name: true } } },
  });

  const cloudConnections = allConnections.filter((connection) => {
    const manifest = getManifest(connection.provider.slug);
    return manifest?.supportsMultipleConnections === true;
  });

  if (cloudConnections.length === 0) {
    logger.info('No active multi-connection cloud connections found');
    return { success: true, connectionsTriggered: 0, totalConnections: 0 };
  }

  logger.info(
    `Found ${cloudConnections.length} active connections with supportsMultipleConnections`,
  );

  const triggerPayloads = cloudConnections.map((connection) => {
    const metadata = (connection.metadata || {}) as Record<string, unknown>;
    const connectionName =
      typeof metadata.connectionName === 'string'
        ? metadata.connectionName
        : connection.provider.name;

    return {
      payload: {
        connectionId: connection.id,
        organizationId: connection.organizationId,
        providerSlug: connection.provider.slug,
        connectionName,
      },
    };
  });

  const BATCH_SIZE = 100;
  let totalTriggered = 0;

  try {
    for (let i = 0; i < triggerPayloads.length; i += BATCH_SIZE) {
      const batch = triggerPayloads.slice(i, i + BATCH_SIZE);
      await runCloudSecurityScan.batchTrigger(batch);
      totalTriggered += batch.length;

      logger.info(
        `Triggered batch ${Math.floor(i / BATCH_SIZE) + 1}: ${batch.length} scans`,
      );
    }

    logger.info(`Successfully triggered ${totalTriggered} cloud security scans`);

    return {
      success: true,
      connectionsTriggered: totalTriggered,
      totalConnections: cloudConnections.length,
    };
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : String(error);

    logger.error('Failed to trigger cloud security scans', {
      error: errorMessage,
      triggeredBeforeError: totalTriggered,
    });

    return {
      success: false,
      connectionsTriggered: totalTriggered,
      totalConnections: cloudConnections.length,
      error: errorMessage,
    };
  }
}

/**
 * Daily scheduled task that triggers cloud security scans for all active
 * multi-connection cloud providers (AWS, Railway, …).
 *
 * Self-hosted: the declarative cron is disabled to stay within the trigger.dev
 * free-tier schedule limit. The orchestration still runs daily — it is invoked
 * from `integrationChecksSchedule` (06:00 UTC) via `orchestrateCloudSecurityScans`.
 * The task is kept so hosted deployments can re-enable the dedicated cron.
 */
export const cloudSecuritySchedule = schedules.task({
  id: 'cloud-security-schedule',
  // Self-hosted: declarative cron disabled to stay within trigger.dev free-tier schedule limit
  // cron: '0 5 * * *', // 5:00 AM UTC daily (same as legacy)
  maxDuration: 1000 * 60 * 30, // 30 minutes for orchestration
  run: async (payload) => {
    logger.info('Starting daily cloud security scan orchestrator', {
      scheduledAt: payload.timestamp,
      lastRun: payload.lastTimestamp,
    });

    return orchestrateCloudSecurityScans();
  },
});
