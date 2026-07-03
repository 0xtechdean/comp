const mockGetManifest = jest.fn();
const mockRunAllChecks = jest.fn();
jest.mock('@trycompai/integration-platform', () => ({
  getManifest: (...args: unknown[]) => mockGetManifest(...args),
  runAllChecks: (...args: unknown[]) => mockRunAllChecks(...args),
}));

import { RAILWAY_SCAN_MODE, scanRailwaySecurityFindings } from './railway-scan';

const baseParams = {
  credentials: { api_key: 'tok' },
  variables: {},
  connectionId: 'conn_1',
  organizationId: 'org_1',
};

const makeResult = (
  overrides: Partial<{
    findings: unknown[];
    passingResults: unknown[];
    status: 'success' | 'failed' | 'error';
    error: string;
  }>,
) => ({
  results: [
    {
      checkId: 'railway-account-2fa',
      checkName: 'Account 2FA',
      status: overrides.status ?? 'failed',
      durationMs: 1,
      error: overrides.error,
      result: {
        findings: overrides.findings ?? [],
        passingResults: overrides.passingResults ?? [],
        logs: [],
      },
    },
  ],
  totalFindings: (overrides.findings ?? []).length,
  totalPassing: (overrides.passingResults ?? []).length,
  durationMs: 1,
});

describe('scanRailwaySecurityFindings', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockGetManifest.mockReturnValue({ id: 'railway', checks: [] });
  });

  it('maps findings and passing results to SecurityFindings, preserving evidence', async () => {
    mockRunAllChecks.mockResolvedValue(
      makeResult({
        findings: [
          {
            title: 'no 2fa',
            description: 'd',
            resourceType: 'railway-account',
            resourceId: 'u1',
            severity: 'high',
            remediation: 'enable it',
            evidence: { serviceId: 'access', findingKey: 'railway-account-2fa' },
          },
        ],
        passingResults: [
          {
            title: 'private project',
            description: 'ok',
            resourceType: 'railway-project',
            resourceId: 'p1',
            evidence: { serviceId: 'exposure' },
          },
        ],
      }),
    );

    const findings = await scanRailwaySecurityFindings(baseParams);

    const fail = findings.find((f) => !f.passed);
    const pass = findings.find((f) => f.passed);
    expect(fail).toMatchObject({
      resourceId: 'u1',
      severity: 'high',
      passed: false,
    });
    expect(fail?.evidence).toMatchObject({ serviceId: 'access' });
    expect(pass).toMatchObject({ resourceId: 'p1', severity: 'info', passed: true });
  });

  it('coerces credentials so the token reaches runAllChecks', async () => {
    mockRunAllChecks.mockResolvedValue(makeResult({ status: 'success' }));
    await scanRailwaySecurityFindings(baseParams);
    expect(mockRunAllChecks).toHaveBeenCalledWith(
      expect.objectContaining({ credentials: { api_key: 'tok' } }),
    );
  });

  it('throws when the railway manifest is not registered', async () => {
    mockGetManifest.mockReturnValue(undefined);
    await expect(scanRailwaySecurityFindings(baseParams)).rejects.toThrow(
      /manifest not found/i,
    );
  });

  it('throws when every check errored (e.g. an invalid token)', async () => {
    mockRunAllChecks.mockResolvedValue(
      makeResult({ status: 'error', error: 'HTTP 401: Unauthorized' }),
    );
    await expect(scanRailwaySecurityFindings(baseParams)).rejects.toThrow(
      /401/,
    );
  });

  it('exposes a stable scan-mode tag', () => {
    expect(RAILWAY_SCAN_MODE).toBe('railway_checks');
  });
});
