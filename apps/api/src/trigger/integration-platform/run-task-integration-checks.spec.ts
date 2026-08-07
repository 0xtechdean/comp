const mockDb = {
  integrationConnection: { findUnique: jest.fn(), update: jest.fn() },
  integrationCheckRun: { create: jest.fn() },
  integrationCheckResult: { createMany: jest.fn() },
  task: { findUnique: jest.fn(), update: jest.fn() },
};

jest.mock('@db', () => ({ db: mockDb }));

// Importing the runner evaluates task() at module load — stub the SDK.
jest.mock('@trigger.dev/sdk', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn() },
  tags: { add: jest.fn() },
  task: (config: unknown) => config,
}));

jest.mock('@trycompai/integration-platform', () => ({
  getManifest: jest.fn(() => null),
  runAllChecks: jest.fn(),
}));

// Delegate to the server path so the credential preflight is skipped — this
// spec is about what gets WRITTEN to the task row, not credential plumbing.
jest.mock('./dynamic-provider', () => ({
  isActiveDynamicProvider: jest.fn().mockResolvedValue(false),
  shouldRunOnServer: jest.fn(() => true),
}));

const mockRunChecksOnServer = jest.fn();
jest.mock('./run-checks-on-server', () => ({
  runChecksOnServer: (...args: unknown[]) => mockRunChecksOnServer(...args),
}));

jest.mock('./ensure-valid-credentials', () => ({
  getAccessToken: jest.fn(() => 'tok'),
  requestValidCredentials: jest.fn(),
}));

jest.mock('../../integration-platform/utils/disabled-task-checks', () => ({
  isCheckDisabledForTask: jest.fn(() => false),
}));

jest.mock('../../cloud-security/finding-exceptions', () => ({
  loadActiveExceptionSet: jest.fn().mockResolvedValue(new Set()),
}));

const mockDecideTaskStatus = jest.fn();
jest.mock('../../integration-platform/utils/task-check-evaluation', () => ({
  countEffectiveFailures: jest.fn(() => 0),
  decideTaskStatus: (...args: unknown[]) => mockDecideTaskStatus(...args),
  decideRunStatus: jest.fn(() => 'success'),
  splitFailuresByDisposition: jest.fn(() => ({ effective: [] })),
  failureSignalsFromEvidence: jest.fn(() => ({})),
}));

import { runTaskIntegrationChecks } from './run-task-integration-checks';

const PAYLOAD = {
  taskId: 'task_1',
  taskTitle: 'Secure Code',
  connectionId: 'conn_1',
  providerSlug: 'github-app',
  organizationId: 'org_1',
  checkIds: ['dependabot_enabled'],
};

// One clean passing check result.
const passingRun = () => ({
  results: [
    {
      checkId: 'dependabot_enabled',
      checkName: 'Dependabot enabled',
      status: 'success',
      durationMs: 5,
      error: undefined,
      result: {
        findings: [],
        passingResults: [
          {
            resourceType: 'repo',
            resourceId: 'r1',
            title: 'ok',
            description: 'ok',
          },
        ],
        summary: { totalChecked: 1 },
        logs: [],
      },
    },
  ],
});

type TaskRunner = {
  run: (payload: typeof PAYLOAD) => Promise<{ success: boolean }>;
};

const runner = runTaskIntegrationChecks as unknown as TaskRunner;

describe('runTaskIntegrationChecks — lastCompletedAt', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockDb.integrationConnection.findUnique.mockResolvedValue({
      id: 'conn_1',
      status: 'active',
      metadata: {},
      variables: {},
    });
    mockDb.integrationConnection.update.mockResolvedValue({});
    mockDb.integrationCheckRun.create.mockResolvedValue({ id: 'icr_1' });
    mockDb.integrationCheckResult.createMany.mockResolvedValue({});
    mockDb.task.update.mockResolvedValue({});
    mockRunChecksOnServer.mockResolvedValue(passingRun());
    mockDecideTaskStatus.mockReturnValue('done');
  });

  // The write that carries the dated evidence a Type 2 period sample reads.
  const taskUpdateData = () => {
    const call = mockDb.task.update.mock.calls.at(-1);
    return call?.[0]?.data as Record<string, unknown> | undefined;
  };

  it('records lastCompletedAt when a passing run transitions the task to done', async () => {
    mockDb.task.findUnique.mockResolvedValue({
      status: 'failed',
      frequency: 'quarterly',
    });

    await runner.run(PAYLOAD);

    const data = taskUpdateData();
    expect(data?.status).toBe('done');
    expect(data?.lastCompletedAt).toBeInstanceOf(Date);
    // A real transition advances the review date.
    expect(data?.reviewDate).toBeInstanceOf(Date);
  });

  it('records lastCompletedAt even when the task was ALREADY done', async () => {
    // The regression: automated controls sit at `done` indefinitely, so a
    // transition-only write leaves them with no evidence of in-period operation.
    mockDb.task.findUnique.mockResolvedValue({
      status: 'done',
      frequency: 'quarterly',
    });

    await runner.run(PAYLOAD);

    const data = taskUpdateData();
    expect(data?.lastCompletedAt).toBeInstanceOf(Date);
    // Not a transition — the review date must stay put, or a daily-passing
    // control walks its own next review out of the audit window.
    expect(data?.reviewDate).toBeUndefined();
  });

  it('does not record lastCompletedAt when the run fails the task', async () => {
    mockDecideTaskStatus.mockReturnValue('failed');
    mockDb.task.findUnique.mockResolvedValue({ status: 'done' });

    await runner.run(PAYLOAD);

    const data = taskUpdateData();
    expect(data?.status).toBe('failed');
    expect(data?.lastCompletedAt).toBeUndefined();
  });
});
