import { db } from '@db';
import { requestValidCredentials } from './ensure-valid-credentials';
import { refreshExpiringTokensSchedule } from './refresh-expiring-tokens-schedule';

jest.mock('@db', () => ({
  db: {
    integrationConnection: { findMany: jest.fn() },
  },
}));

jest.mock('@trigger.dev/sdk', () => ({
  logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn() },
  schedules: {
    task: (config: unknown) => config,
  },
}));

jest.mock('./ensure-valid-credentials', () => ({
  requestValidCredentials: jest.fn(),
}));

/**
 * The mocked `schedules.task` returns its config object verbatim, so `run` is
 * callable here even though the real SDK's `Task` type does not expose it.
 * Only the two fields the task actually reads are modelled.
 */
const runSchedule = (
  refreshExpiringTokensSchedule as unknown as {
    run: (payload: { timestamp: Date; lastTimestamp?: Date }) => Promise<{
      refreshed: number;
      failed: number;
      skipped: number;
      total?: number;
    }>;
  }
).run;

describe('refreshExpiringTokensSchedule', () => {
  const nowMs = Date.parse('2026-04-24T00:00:00.000Z');
  const originalApiUrl = process.env.API_URL;

  beforeEach(() => {
    // The task reads `new Date()`, not `Date.now()`, so a spy on Date.now alone
    // left it comparing the fixtures against the real clock — every fixture read
    // as already expired and nothing was ever selected for refresh.
    jest.useFakeTimers({ now: nowMs });
    // Without API_URL the task logs an error and returns zeroed counters before
    // it ever queries, so every assertion below would pass vacuously at 0.
    process.env.API_URL = 'https://api.test.local';
    (requestValidCredentials as jest.Mock).mockResolvedValue({ success: true });
  });

  afterEach(() => {
    jest.useRealTimers();
    jest.restoreAllMocks();
    jest.clearAllMocks();
    if (originalApiUrl === undefined) {
      delete process.env.API_URL;
      return;
    }
    process.env.API_URL = originalApiUrl;
  });

  it('refreshes only connections whose latest credential version expires soon', async () => {
    const connectionWithOldVersionExpiringSoon = {
      id: 'conn_old_soon',
      providerSlug: 'example',
      organizationId: 'org_1',
      organization: { id: 'org_1', name: 'Org 1' },
      credentialVersions: [
        { expiresAt: new Date('2026-04-26T00:00:00.000Z') },
        { expiresAt: new Date('2026-04-24T12:00:00.000Z') },
      ],
    };

    const connectionWithLatestExpiringSoon = {
      id: 'conn_latest_soon',
      providerSlug: 'example',
      organizationId: 'org_2',
      organization: { id: 'org_2', name: 'Org 2' },
      credentialVersions: [{ expiresAt: new Date('2026-04-24T12:00:00.000Z') }],
    };

    (db.integrationConnection.findMany as jest.Mock).mockResolvedValue([
      connectionWithOldVersionExpiringSoon,
      connectionWithLatestExpiringSoon,
    ]);

    const result = await runSchedule({ timestamp: new Date(nowMs) });

    expect(result.refreshed).toBe(1);
    expect(requestValidCredentials).toHaveBeenCalledTimes(1);
    expect(requestValidCredentials).toHaveBeenCalledWith({
      apiUrl: expect.any(String),
      connectionId: 'conn_latest_soon',
      organizationId: 'org_2',
      forceRefresh: true,
    });
  });

  it('skips connections whose latest version is not expiring soon', async () => {
    const connectionLatestValid = {
      id: 'conn_latest_valid',
      providerSlug: 'example',
      organizationId: 'org_3',
      organization: { id: 'org_3', name: 'Org 3' },
      credentialVersions: [{ expiresAt: new Date('2026-04-25T12:00:00.000Z') }],
    };

    (db.integrationConnection.findMany as jest.Mock).mockResolvedValue([
      connectionLatestValid,
    ]);

    const result = await runSchedule({ timestamp: new Date(nowMs) });

    expect(result.refreshed).toBe(0);
    expect(requestValidCredentials).not.toHaveBeenCalled();
  });
});
