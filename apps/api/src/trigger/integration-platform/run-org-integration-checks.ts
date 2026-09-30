import { db } from '@db';
import { logger, queue, task } from '@trigger.dev/sdk';
import {
  sendBundledFailureEmails,
  type FailedTaskSummary,
} from './org-failure-email';
import {
  runTaskIntegrationChecks,
  type TaskCheckRunResult,
} from './run-task-integration-checks';

/** One task scheduled for an org, as handed down by the orchestrator. */
export interface OrgTaskCheck {
  taskId: string;
  taskTitle: string;
  connectionId: string;
  providerSlug: string;
  checkIds: string[];
}

type FailureCounts = Map<string, { failedCount: number; totalCount: number }>;

// Bound how many per-org runners wait concurrently. The child checks run on the
// default queue at full env concurrency; only the PARENTS are capped here, so a
// day with many orgs can't pin the whole environment with runners that are
// merely suspended waiting on their children.
const orgRunnerQueue = queue({
  name: 'integration-checks-org-runner',
  concurrencyLimit: 50,
});

// Chunk large orgs: batchTriggerAndWait accepts a bounded number of items per
// call (the orchestrator already self-limits its own triggers the same way).
const CHILD_BATCH_SIZE = 100;

/**
 * Sum the "(X/Y failed)" counts per task from the child runs that ended with the
 * task `failed`. A task checked over several connections (e.g. 2FA on GitHub +
 * Google Workspace) gets one child run per connection, so counts are summed.
 * Errored/crashed children (`!ok`) contribute nothing. Pure + exported for tests.
 */
export function collectFailureCounts(
  runs: Array<{ ok: boolean; output?: TaskCheckRunResult }>,
  into: FailureCounts = new Map(),
): FailureCounts {
  for (const run of runs) {
    if (!run.ok || !run.output || run.output.success !== true) continue;
    if (run.output.taskStatus !== 'failed') continue;
    const prev = into.get(run.output.taskId) ?? {
      failedCount: 0,
      totalCount: 0,
    };
    into.set(run.output.taskId, {
      failedCount: prev.failedCount + run.output.failedCount,
      totalCount: prev.totalCount + run.output.totalCount,
    });
  }
  return into;
}

/**
 * Every scheduled task whose status is `failed` AFTER this run, read from the
 * DB — not just the tasks this run flipped into `failed`. Reporting only
 * transitions meant a task that stayed red was named once and then went silent
 * every day after, so the digest said "0 failed" while a control was broken.
 * The DB is the source of truth because a task checked over several
 * connections ends in whatever state its last child wrote.
 */
export async function findCurrentlyFailedTasks(params: {
  organizationId: string;
  taskIds: string[];
  counts: FailureCounts;
}): Promise<FailedTaskSummary[]> {
  const { organizationId, taskIds, counts } = params;
  if (taskIds.length === 0) return [];

  const failed = await db.task.findMany({
    where: { id: { in: taskIds }, organizationId, status: 'failed' },
    select: { id: true, title: true },
    orderBy: { title: 'asc' },
  });

  return failed.map((t) => ({
    taskId: t.id,
    taskTitle: t.title,
    failedCount: counts.get(t.id)?.failedCount ?? 0,
    totalCount: counts.get(t.id)?.totalCount ?? 0,
  }));
}

/**
 * Per-org runner. The daily orchestrator dispatches ONE of these per org
 * (fire-and-forget). It runs that org's due integration checks in parallel via
 * batchTriggerAndWait, then sends a SINGLE bundled email listing every task that
 * is currently failing — instead of one email per failing task.
 *
 * Mirrors the established in-repo nested fan-out pattern (e.g. onboarding's
 * per-org runners that batchTriggerAndWait their work internally).
 */
export const runOrgIntegrationChecks = task({
  id: 'run-org-integration-checks',
  queue: orgRunnerQueue,
  // maxDuration is max COMPUTE time in SECONDS (the suspended wait during
  // batchTriggerAndWait is checkpointed and doesn't count against it). 1h is
  // ample for the runner's own work (collect results + send emails) and matches
  // the sibling batchTriggerAndWait orchestrator (process-knowledge-base-documents).
  maxDuration: 60 * 60, // 1 hour (in seconds)
  run: async (payload: {
    organizationId: string;
    organizationName: string;
    tasks: OrgTaskCheck[];
  }) => {
    const { organizationId, organizationName, tasks } = payload;

    logger.info(
      `Running integration checks for org ${organizationId} (${tasks.length} task(s))`,
    );

    if (tasks.length === 0) {
      return { organizationId, tasksRun: 0, failedTasks: 0, emailed: false };
    }

    const counts: FailureCounts = new Map();

    for (let i = 0; i < tasks.length; i += CHILD_BATCH_SIZE) {
      const batch = tasks.slice(i, i + CHILD_BATCH_SIZE);
      const batchResult = await runTaskIntegrationChecks.batchTriggerAndWait(
        batch.map((t) => ({
          payload: {
            taskId: t.taskId,
            taskTitle: t.taskTitle,
            connectionId: t.connectionId,
            providerSlug: t.providerSlug,
            organizationId,
            checkIds: t.checkIds,
          },
        })),
      );
      collectFailureCounts(batchResult.runs, counts);
    }

    const failedTasks = await findCurrentlyFailedTasks({
      organizationId,
      taskIds: [...new Set(tasks.map((t) => t.taskId))],
      counts,
    });

    logger.info(
      `Org ${organizationId}: ${failedTasks.length} task(s) currently failing after checks`,
    );

    await sendBundledFailureEmails({
      organizationId,
      organizationName,
      failedTasks,
    });

    return {
      organizationId,
      tasksRun: tasks.length,
      failedTasks: failedTasks.length,
      emailed: failedTasks.length > 0,
    };
  },
});
