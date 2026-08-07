import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException } from '@nestjs/common';
import { AdminFindingsController } from './admin-findings.controller';
import { FindingsService } from '../findings/findings.service';

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

jest.mock('@db', () => ({
  // Enums this spec does not name are still read at module scope further down
  // the import chain; pull them all in, then let the explicit stubs below win.
  ...jest.requireActual('@prisma/client'),
  db: {},
  FindingStatus: {
    open: 'open',
    ready_for_review: 'ready_for_review',
    needs_revision: 'needs_revision',
    closed: 'closed',
  },
  FindingType: {
    soc2: 'soc2',
    iso27001: 'iso27001',
  },
}));

// `@trycompai/auth`'s barrel re-exports the permission tables, which import
// better-auth — shipped ESM-only, and jest cannot transform it. This spec never
// exercises permissions; it just sits downstream of a chain that imports the
// barrel. Keep the participation half real (no better-auth dependency) and stub
// the rest.
jest.mock('@trycompai/auth', () => ({
  ...jest.requireActual('@trycompai/auth/participation'),
  BUILT_IN_ROLE_OBLIGATIONS: {},
  allRoles: {},
}));

describe('AdminFindingsController', () => {
  let controller: AdminFindingsController;

  const mockService = {
    listForOrganization: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
    delete: jest.fn(),
  };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AdminFindingsController],
      providers: [{ provide: FindingsService, useValue: mockService }],
    }).compile();

    controller = module.get<AdminFindingsController>(AdminFindingsController);
    jest.clearAllMocks();
  });

  describe('list', () => {
    it('should list findings for an organization', async () => {
      const findings = [{ id: 'fnd_1', status: 'open' }];
      mockService.listForOrganization.mockResolvedValue(findings);

      const result = await controller.list('org_1');

      // The status filter moved into an options object.
      expect(mockService.listForOrganization).toHaveBeenCalledWith('org_1', {
        status: undefined,
      });
      expect(result).toEqual(findings);
    });

    it('should filter by status', async () => {
      mockService.listForOrganization.mockResolvedValue([]);

      await controller.list('org_1', 'open');

      expect(mockService.listForOrganization).toHaveBeenCalledWith('org_1', {
        status: 'open',
      });
    });

    it('should reject invalid status', async () => {
      await expect(controller.list('org_1', 'invalid')).rejects.toThrow(
        BadRequestException,
      );
    });
  });

  describe('create', () => {
    it('should create a finding with null memberId', async () => {
      const dto = { content: 'Test finding', taskId: 'tsk_1' };
      const created = { id: 'fnd_1', ...dto };
      mockService.create.mockResolvedValue(created);

      const result = await controller.create('org_1', dto as never, {
        userId: 'usr_admin',
      });

      expect(mockService.create).toHaveBeenCalledWith(
        'org_1',
        null,
        'usr_admin',
        dto,
      );
      expect(result).toEqual(created);
    });
  });

  describe('update', () => {
    it('should update a finding as platform admin', async () => {
      const dto = { status: 'closed' };
      const updated = { id: 'fnd_1', status: 'closed' };
      mockService.update.mockResolvedValue(updated);

      const result = await controller.update('org_1', 'fnd_1', dto as never, {
        userId: 'usr_admin',
      });

      expect(mockService.update).toHaveBeenCalledWith(
        'org_1',
        'fnd_1',
        dto,
        // Was a roles array; now a `canCreateFindings` flag, which a platform
        // admin always satisfies.
        true,
        true,
        'usr_admin',
        null,
      );
      expect(result).toEqual(updated);
    });
  });

  describe('remove', () => {
    it('should delete a finding as platform admin', async () => {
      const deleted = {
        message: 'Finding deleted successfully',
        deletedFinding: { id: 'fnd_1' },
      };
      mockService.delete.mockResolvedValue(deleted);

      const result = await controller.remove('org_1', 'fnd_1', {
        userId: 'usr_admin',
      });

      expect(mockService.delete).toHaveBeenCalledWith(
        'org_1',
        'fnd_1',
        'usr_admin',
        null,
      );
      expect(result).toEqual(deleted);
    });
  });
});
