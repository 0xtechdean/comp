import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException } from '@nestjs/common';
import { AdminEvidenceController } from './admin-evidence.controller';
import { EvidenceFormsService } from '../evidence-forms/evidence-forms.service';

jest.mock('../auth/platform-admin.guard', () => ({
  PlatformAdminGuard: class {
    canActivate() {
      return true;
    }
  },
}));

jest.mock('../auth/auth.server', () => ({
  auth: { api: {} },
}));

// '@db' re-exports every Prisma enum alongside the client. The chain below
// reads enums at module scope, so a bare `{ db: {} }` stub left them undefined.
// Take the enums from '@prisma/client' — that gets them without constructing a
// client — and stub only `db` itself.
jest.mock('@db', () => ({
  ...jest.requireActual('@prisma/client'),
  db: {},
}));
// `@trycompai/auth`'s barrel re-exports the permission tables, which import
// better-auth — shipped ESM-only, and jest cannot transform it. This spec never
// exercises permissions (the service is mocked wholesale); it just sits
// downstream of a chain that imports the barrel. Keep the participation half
// real (it has no better-auth dependency) and stub the rest.
jest.mock('@trycompai/auth', () => ({
  ...jest.requireActual('@trycompai/auth/participation'),
  BUILT_IN_ROLE_OBLIGATIONS: {},
  allRoles: {},
}));


describe('AdminEvidenceController', () => {
  let controller: AdminEvidenceController;

  const mockService = {
    getFormStatuses: jest.fn(),
    getFormWithSubmissions: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AdminEvidenceController],
      providers: [{ provide: EvidenceFormsService, useValue: mockService }],
    }).compile();

    controller = module.get<AdminEvidenceController>(AdminEvidenceController);
    jest.clearAllMocks();
  });

  describe('listFormStatuses', () => {
    it('should return form statuses', async () => {
      const statuses = {
        'access-request': { lastSubmittedAt: '2026-01-01' },
        meeting: { lastSubmittedAt: null },
      };
      mockService.getFormStatuses.mockResolvedValue(statuses);

      const result = await controller.listFormStatuses('org_1');

      expect(mockService.getFormStatuses).toHaveBeenCalledWith('org_1');
      expect(result).toEqual(statuses);
    });
  });

  describe('getFormWithSubmissions', () => {
    it('should return form with submissions', async () => {
      const detail = {
        form: { type: 'meeting', label: 'Meeting' },
        submissions: [],
        total: 0,
      };
      mockService.getFormWithSubmissions.mockResolvedValue(detail);
      const mockReq = { userId: 'usr_admin1' };

      const result = await controller.getFormWithSubmissions(
        'org_1',
        'meeting',
        mockReq,
      );

      expect(mockService.getFormWithSubmissions).toHaveBeenCalledWith({
        organizationId: 'org_1',
        authContext: expect.objectContaining({
          userId: 'usr_admin1',
          isPlatformAdmin: true,
          isApiKey: false,
          userRoles: ['admin'],
        }),
        formType: 'meeting',
        search: undefined,
        limit: undefined,
        offset: undefined,
      });
      expect(result).toEqual(detail);
    });

    it('should reject empty formType', async () => {
      const mockReq = { userId: 'usr_admin1' };
      await expect(
        controller.getFormWithSubmissions('org_1', '', mockReq),
      ).rejects.toThrow(BadRequestException);
    });
  });
});
