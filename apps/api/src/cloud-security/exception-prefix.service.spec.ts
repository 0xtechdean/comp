import { BadRequestException, ForbiddenException } from '@nestjs/common';

const dbMock = {
  integrationConnection: { findFirst: jest.fn() },
  findingException: { upsert: jest.fn() },
};
jest.mock('@db', () => ({ db: dbMock }));

const auditLogMock = jest.fn().mockResolvedValue(undefined);
jest.mock('./cloud-security-audit', () => ({
  logCloudSecurityActivity: auditLogMock,
}));

import { CloudPrefixExceptionService } from './exception-prefix.service';

const DAY_MS = 24 * 60 * 60 * 1000;
const inDays = (days: number) => new Date(Date.now() + days * DAY_MS);

function validInput(overrides: Record<string, unknown> = {}) {
  return {
    organizationId: 'org_1',
    connectionId: 'icn_aws',
    checkIdPrefix: 'secrets-no-rotation-cloud/stacks/dep_',
    resourceIdPrefix:
      'arn:aws:secretsmanager:eu-central-1:111:secret:cloud/stacks/dep_',
    userId: 'usr_1',
    reason: 'One secret bundle per stack, written once by the provisioner.',
    reviewedBy: 'CTO, monthly review',
    expiresAt: inDays(300),
    ...overrides,
  };
}

describe('CloudPrefixExceptionService.markPrefixException', () => {
  const service = new CloudPrefixExceptionService();

  beforeEach(() => {
    jest.clearAllMocks();
    dbMock.integrationConnection.findFirst.mockResolvedValue({ id: 'icn_aws' });
    dbMock.findingException.upsert.mockResolvedValue({ id: 'fex_class' });
  });

  it('upserts a prefix row on the connection and audits it', async () => {
    const input = validInput();
    const result = await service.markPrefixException(input);

    expect(result).toEqual({ id: 'fex_class' });
    expect(dbMock.integrationConnection.findFirst).toHaveBeenCalledWith({
      where: { id: 'icn_aws', organizationId: 'org_1' },
      select: { id: true },
    });
    const call = dbMock.findingException.upsert.mock.calls[0][0];
    expect(call.where.organizationId_connectionId_checkId_resourceId).toEqual({
      organizationId: 'org_1',
      connectionId: 'icn_aws',
      checkId: input.checkIdPrefix,
      resourceId: input.resourceIdPrefix,
    });
    expect(call.create).toEqual(
      expect.objectContaining({
        match: 'prefix',
        expiresAt: input.expiresAt,
        markedById: 'usr_1',
      }),
    );
    // Re-marking a revoked class exception reopens the same row.
    expect(call.update).toEqual(
      expect.objectContaining({
        match: 'prefix',
        revokedAt: null,
        revokedById: null,
      }),
    );
    expect(auditLogMock).toHaveBeenCalledWith(
      expect.objectContaining({
        action: 'exception_marked',
        connectionId: 'icn_aws',
        metadata: expect.objectContaining({
          match: 'prefix',
          exceptionId: 'fex_class',
        }),
      }),
    );
  });

  it('prefixes the audit description with the caller label for API-key callers', async () => {
    await service.markPrefixException(
      validInput({ callerLabel: 'via API key "ops"' }),
    );
    expect(auditLogMock.mock.calls[0][0].description).toMatch(
      /^\[via API key "ops"\] Marked every finding matching/,
    );
  });

  it.each([
    ['a short reason', { reason: 'too short' }],
    ['a short check prefix', { checkIdPrefix: 'secret' }],
    ['a short resource prefix', { resourceIdPrefix: 'arn:aws' }],
    ['a whitespace-padded short prefix', { checkIdPrefix: '   secret   ' }],
    ['no expiry', { expiresAt: null }],
    ['a past expiry', { expiresAt: inDays(-1) }],
    ['an expiry more than a year out', { expiresAt: inDays(400) }],
  ])('rejects %s without writing', async (_label, overrides) => {
    await expect(
      service.markPrefixException(validInput(overrides)),
    ).rejects.toThrow(BadRequestException);
    expect(dbMock.findingException.upsert).not.toHaveBeenCalled();
    expect(auditLogMock).not.toHaveBeenCalled();
  });

  it("refuses a connection outside the caller's organization", async () => {
    dbMock.integrationConnection.findFirst.mockResolvedValueOnce(null);
    await expect(service.markPrefixException(validInput())).rejects.toThrow(
      ForbiddenException,
    );
    expect(dbMock.findingException.upsert).not.toHaveBeenCalled();
  });
});
