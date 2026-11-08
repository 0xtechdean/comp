// Stub the dependencies HybridAuthGuard pulls in, as in
// cloud-security.controller.spec.ts; guards are tested elsewhere.
jest.mock('@db', () => ({ db: {} }));
jest.mock('@trycompai/auth', () => ({
  statement: {},
  ac: { newRole: () => ({}) },
}));
jest.mock('../auth/auth.server', () => ({
  auth: { api: { getSession: jest.fn() } },
}));

import { Test, TestingModule } from '@nestjs/testing';
import { HttpException } from '@nestjs/common';
import { CloudSecurityExceptionsController } from './cloud-security-exceptions.controller';
import { CloudPrefixExceptionService } from './exception-prefix.service';
import { ActingUserResolver } from '../auth/acting-user.service';
import { HybridAuthGuard } from '../auth/hybrid-auth.guard';
import { PermissionGuard } from '../auth/permission.guard';
import type { AuthenticatedRequest } from '../auth/types';

describe('CloudSecurityExceptionsController.markPrefixException', () => {
  let controller: CloudSecurityExceptionsController;
  const prefixExceptions = { markPrefixException: jest.fn() };
  const actingUser = { resolve: jest.fn() };
  const req = { isApiKey: true } as unknown as AuthenticatedRequest;
  const body = {
    connectionId: 'icn_aws',
    checkIdPrefix: 'secrets-no-rotation-cloud/stacks/dep_',
    resourceIdPrefix:
      'arn:aws:secretsmanager:eu-central-1:111:secret:cloud/stacks/dep_',
    reason: 'One secret bundle per stack, written once by the provisioner.',
    expiresAt: '2027-10-31',
  };

  beforeEach(async () => {
    jest.clearAllMocks();
    const module: TestingModule = await Test.createTestingModule({
      controllers: [CloudSecurityExceptionsController],
      providers: [
        { provide: CloudPrefixExceptionService, useValue: prefixExceptions },
        { provide: ActingUserResolver, useValue: actingUser },
      ],
    })
      .overrideGuard(HybridAuthGuard)
      .useValue({ canActivate: () => true })
      .overrideGuard(PermissionGuard)
      .useValue({ canActivate: () => true })
      .compile();
    controller = module.get(CloudSecurityExceptionsController);
  });

  it('passes the body, acting user and parsed expiry to the service', async () => {
    actingUser.resolve.mockResolvedValueOnce({
      userId: 'usr_owner',
      source: 'org-owner-fallback',
      callerLabel: 'via API key "ops"',
    });
    prefixExceptions.markPrefixException.mockResolvedValueOnce({
      id: 'fex_class',
    });

    const result = await controller.markPrefixException(body, 'org_1', req);

    expect(result).toEqual({ data: { id: 'fex_class' } });
    const input = prefixExceptions.markPrefixException.mock.calls[0][0];
    expect(input).toEqual(
      expect.objectContaining({
        organizationId: 'org_1',
        connectionId: 'icn_aws',
        checkIdPrefix: body.checkIdPrefix,
        resourceIdPrefix: body.resourceIdPrefix,
        userId: 'usr_owner',
        reviewedBy: null,
        callerLabel: 'via API key "ops"',
      }),
    );
    // A bare date runs to the end of that day in UTC (parseExceptionExpiry).
    expect(input.expiresAt.toISOString()).toBe('2027-10-31T23:59:59.999Z');
  });

  it('returns 400 when no user can be attributed', async () => {
    actingUser.resolve.mockResolvedValueOnce({ userId: null, source: 'none' });
    await expect(
      controller.markPrefixException(body, 'org_1', req),
    ).rejects.toThrow(HttpException);
    expect(prefixExceptions.markPrefixException).not.toHaveBeenCalled();
  });
});
