import { Test, TestingModule } from '@nestjs/testing';
import { BadRequestException } from '@nestjs/common';
import { AdminTasksController } from './admin-tasks.controller';
import { TasksService } from '../tasks/tasks.service';
import { CommentsService } from '../comments/comments.service';
import { AttachmentsService } from '../attachments/attachments.service';

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
  TaskStatus: {
    todo: 'todo',
    in_progress: 'in_progress',
    done: 'done',
    not_applicable: 'not_applicable',
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

describe('AdminTasksController', () => {
  let controller: AdminTasksController;

  const mockService = {
    getTasks: jest.fn(),
    updateTask: jest.fn(),
    createTask: jest.fn(),
  };

  const mockCommentsService = { getComments: jest.fn() };
  const mockAttachmentsService = { getAttachments: jest.fn() };

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AdminTasksController],
      providers: [
        { provide: TasksService, useValue: mockService },
        { provide: CommentsService, useValue: mockCommentsService },
        { provide: AttachmentsService, useValue: mockAttachmentsService },
      ],
    }).compile();

    controller = module.get<AdminTasksController>(AdminTasksController);
    jest.clearAllMocks();
  });

  describe('list', () => {
    it('should list tasks for an organization', async () => {
      const tasks = { data: [{ id: 'tsk_1' }], count: 1 };
      mockService.getTasks.mockResolvedValue(tasks);

      const result = await controller.list('org_1');

      expect(mockService.getTasks).toHaveBeenCalledWith(
        'org_1',
        {},
        { includeRelations: true },
      );
      expect(result).toEqual(tasks);
    });
  });

  describe('create', () => {
    it('should create a task with required fields', async () => {
      const created = { id: 'tsk_new', title: 'New Task', status: 'todo' };
      mockService.createTask.mockResolvedValue(created);

      const result = await controller.create('org_1', {
        title: 'New Task',
        description: 'A test task',
      });

      expect(mockService.createTask).toHaveBeenCalledWith('org_1', {
        title: 'New Task',
        description: 'A test task',
        frequency: null,
        department: null,
      });
      expect(result).toEqual(created);
    });

    it('should create a task with all optional fields', async () => {
      const created = { id: 'tsk_new', title: 'Full Task', status: 'todo' };
      mockService.createTask.mockResolvedValue(created);

      const result = await controller.create('org_1', {
        title: 'Full Task',
        description: 'Detailed task',
        frequency: 'monthly',
        department: 'it',
      });

      expect(mockService.createTask).toHaveBeenCalledWith('org_1', {
        title: 'Full Task',
        description: 'Detailed task',
        frequency: 'monthly',
        department: 'it',
      });
      expect(result).toEqual(created);
    });
  });

  describe('update', () => {
    it('should update task status', async () => {
      const updated = { id: 'tsk_1', status: 'done' };
      mockService.updateTask.mockResolvedValue(updated);

      const result = await controller.update(
        'org_1',
        'tsk_1',
        { status: 'done' },
        { userId: 'usr_admin' },
      );

      expect(mockService.updateTask).toHaveBeenCalledWith(
        'org_1',
        'tsk_1',
        { status: 'done' },
        'usr_admin',
      );
      expect(result).toEqual(updated);
    });

    it('should reject missing status', async () => {
      await expect(
        controller.update('org_1', 'tsk_1', {}, { userId: 'usr_admin' }),
      ).rejects.toThrow(BadRequestException);
    });

    it('should reject invalid status', async () => {
      await expect(
        controller.update(
          'org_1',
          'tsk_1',
          { status: 'invalid' },
          { userId: 'usr_admin' },
        ),
      ).rejects.toThrow(BadRequestException);
    });
  });
});
