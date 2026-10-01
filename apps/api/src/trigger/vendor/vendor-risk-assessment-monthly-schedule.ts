import { db } from '@db';
import { logger, schedules } from '@trigger.dev/sdk';
import { vendorRiskAssessmentTask } from './vendor-risk-assessment-task';
import {
  REFRESH_SKIP_WINDOW_DAYS,
  partitionVendorsDueForRefresh,
} from './vendor-risk-assessment/refresh-due';

/**
 * Monthly scheduled task that refreshes risk assessments for all vendors,
 * except those whose domain was researched within REFRESH_SKIP_WINDOW_DAYS.
 * Runs on the 1st of each month at 2:00 AM UTC.
 */
export const vendorRiskAssessmentMonthlySchedule = schedules.task({
  id: 'vendor-risk-assessment-monthly-schedule',
  cron: '0 2 1 * *', // 1st of each month at 2:00 AM UTC
  maxDuration: 1000 * 60 * 60, // 1 hour (for batch processing)
  run: async (payload) => {
    logger.info('Monthly vendor risk assessment refresh started', {
      scheduledAt: payload.timestamp,
      lastRun: payload.lastTimestamp,
    });

    // Find all vendors across all organizations that have websites
    const vendors = await db.vendor.findMany({
      where: {
        website: {
          not: null,
        },
      },
      select: {
        id: true,
        name: true,
        website: true,
        organizationId: true,
      },
    });

    logger.info(`Found ${vendors.length} unique vendors with websites`);

    if (vendors.length === 0) {
      return {
        success: true,
        totalVendors: 0,
        triggered: 0,
        message: 'No vendors with websites found',
      };
    }

    const cutoff = new Date(
      Date.now() - REFRESH_SKIP_WINDOW_DAYS * 24 * 60 * 60 * 1000,
    );
    const recentlyAssessed = await db.globalVendors.findMany({
      where: { riskAssessmentUpdatedAt: { gte: cutoff } },
      select: { website: true },
    });
    const { due, skipped } = partitionVendorsDueForRefresh({
      vendors,
      recentlyAssessedWebsites: recentlyAssessed.map((g) => g.website),
    });

    logger.info(
      `Refreshing ${due.length} vendor(s); skipping ${skipped.length} assessed in the last ${REFRESH_SKIP_WINDOW_DAYS} days`,
      { skipped: skipped.map((v) => v.name) },
    );

    if (due.length === 0) {
      return {
        success: true,
        totalVendors: vendors.length,
        skipped: skipped.length,
        triggered: 0,
        message: 'All vendors were assessed recently',
      };
    }

    // Batch trigger risk assessment tasks with research enabled:
    // - Create new assessments for vendors without data (v1)
    // - Refresh existing assessments and increment version (v1 -> v2, v2 -> v3, etc.)
    const batch = due.map((vendor) => ({
      payload: {
        vendorId: vendor.id,
        vendorName: vendor.name,
        vendorWebsite: vendor.website!,
        organizationId: vendor.organizationId,
        createdByUserId: null, // System-initiated
        withResearch: true, // Always do research for monthly refresh
      },
    }));

    try {
      await vendorRiskAssessmentTask.batchTrigger(batch);
      logger.info(`Triggered ${batch.length} vendor risk assessment tasks`, {
        totalVendors: vendors.length,
        triggered: batch.length,
      });

      return {
        success: true,
        totalVendors: vendors.length,
        skipped: skipped.length,
        triggered: batch.length,
        message: `Triggered monthly refresh for ${batch.length} vendors`,
      };
    } catch (error) {
      logger.error('Failed to trigger batch risk assessment tasks', {
        error: error instanceof Error ? error.message : String(error),
        batchSize: batch.length,
      });

      return {
        success: false,
        totalVendors: vendors.length,
        skipped: skipped.length,
        triggered: 0,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  },
});
