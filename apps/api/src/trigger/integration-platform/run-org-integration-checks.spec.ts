const mockDb = {
  task: { findMany: jest.fn() },
};

jest.mock('@db', () => ({ db: mockDb }));

// Importing the runner evaluates queue()/task() at module load — stub them.
// runTaskIntegrationChecks is only referenced inside the task body (not load).
jest.mock('@trigger.dev/sdk', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn() },
  queue: jest.fn(() => ({ name: 'q' })),
  task: (config: unknown) => config,
}));
jest.mock('./run-task-integration-checks', () => ({
  runTaskIntegrationChecks: { batchTriggerAndWait: jest.fn() },
}));
jest.mock('./org-failure-email', () => ({
  sendBundledFailureEmails: jest.fn(),
}));

import {
  collectFailureCounts,
  findCurrentlyFailedTasks,
} from './run-org-integration-checks';
import type { TaskCheckRunResult } from './run-task-integration-checks';

const okRun = (
  output: Partial<Extract<TaskCheckRunResult, { success: true }>> & {
    taskId: string;
  },
): { ok: true; output: TaskCheckRunResult } => ({
  ok: true,
  output: {
    success: true,
    taskTitle: output.taskId,
    checksRun: 1,
    totalPassing: 0,
    totalFindings: 0,
    taskStatus: 'failed',
    statusChangedToFailed: true,
    failedCount: 1,
    totalCount: 1,
    ...output,
  },
});

describe('collectFailureCounts', () => {
  it('counts failing runs whether or not they transitioned, dropping errored and passing runs', () => {
    const counts = collectFailureCounts([
      okRun({ taskId: 't1', failedCount: 2, totalCount: 9 }),
      // Already failed before this run — still counted (the old digest dropped it).
      okRun({
        taskId: 't2',
        statusChangedToFailed: false,
        failedCount: 6,
        totalCount: 7,
      }),
      okRun({ taskId: 't3', taskStatus: 'done', statusChangedToFailed: false }),
      { ok: false },
      { ok: true, output: { success: false, taskId: 't4', error: 'boom' } },
    ]);

    expect(Object.fromEntries(counts)).toEqual({
      t1: { failedCount: 2, totalCount: 9 },
      t2: { failedCount: 6, totalCount: 7 },
    });
  });

  it('sums counts for a task checked over several connections and across batches', () => {
    const counts = collectFailureCounts([
      okRun({ taskId: 't1', failedCount: 1, totalCount: 1 }),
    ]);
    collectFailureCounts(
      [okRun({ taskId: 't1', failedCount: 2, totalCount: 5 })],
      counts,
    );

    expect(counts.get('t1')).toEqual({ failedCount: 3, totalCount: 6 });
  });
});

describe('findCurrentlyFailedTasks', () => {
  beforeEach(() => jest.clearAllMocks());

  it('reports every task that is failed in the DB, including ones that were already failed', async () => {
    mockDb.task.findMany.mockResolvedValue([
      { id: 't2', title: 'Secure Code' },
      { id: 't5', title: 'Errored Child' },
    ]);

    const failed = await findCurrentlyFailedTasks({
      organizationId: 'org1',
      taskIds: ['t1', 't2', 't5'],
      counts: new Map([['t2', { failedCount: 6, totalCount: 7 }]]),
    });

    expect(mockDb.task.findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: {
          id: { in: ['t1', 't2', 't5'] },
          organizationId: 'org1',
          status: 'failed',
        },
      }),
    );
    expect(failed).toEqual([
      { taskId: 't2', taskTitle: 'Secure Code', failedCount: 6, totalCount: 7 },
      // No failing child output (e.g. the child errored) → zero counts, still reported.
      {
        taskId: 't5',
        taskTitle: 'Errored Child',
        failedCount: 0,
        totalCount: 0,
      },
    ]);
  });

  it('skips the query when there are no tasks', async () => {
    await expect(
      findCurrentlyFailedTasks({
        organizationId: 'org1',
        taskIds: [],
        counts: new Map(),
      }),
    ).resolves.toEqual([]);
    expect(mockDb.task.findMany).not.toHaveBeenCalled();
  });
});
