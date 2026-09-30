import { db } from '@db';
import { logger } from '@trigger.dev/sdk';
import { isUserUnsubscribed } from '@trycompai/email';
import { triggerEmail } from '../../email/trigger-email';
import { AutomationBulkFailuresEmail } from '../../email/templates/automation-bulk-failures';

/** A task that is currently `failed` after this run (new or still failing). */
export interface FailedTaskSummary {
  taskId: string;
  taskTitle: string;
  failedCount: number;
  totalCount: number;
}

type Recipient = { id: string; name: string; email: string };

function toRecipient(user: {
  id: string;
  name: string | null;
  email: string;
}): Recipient {
  return {
    id: user.id,
    name: user.name?.trim() || user.email.trim() || 'User',
    email: user.email,
  };
}

/**
 * Recipients for an org's bundled failure email: the assignees of the failed
 * tasks UNION the org's admins/owners (by EXACT member-role token), deduped by
 * user id. Mirrors the canonical getOwnerAdminRecipients resolver in
 * task-notifier.service.ts.
 *
 * Note the deliberate product change: every recipient receives the FULL org
 * digest (every task currently failing), so a non-admin assignee now sees the
 * org's other failed tasks too — not just their own. This is the intended
 * "one bundled email per org" behavior (replacing one email per failing task).
 */
async function resolveRecipients(params: {
  organizationId: string;
  failedTaskIds: string[];
}): Promise<Recipient[]> {
  const { organizationId, failedTaskIds } = params;

  const [tasks, allMembers] = await Promise.all([
    db.task.findMany({
      where: { id: { in: failedTaskIds }, organizationId },
      select: {
        assignee: {
          select: { user: { select: { id: true, name: true, email: true } } },
        },
      },
    }),
    db.member.findMany({
      where: {
        organizationId,
        deactivated: false,
      },
      select: {
        role: true,
        user: { select: { id: true, name: true, email: true } },
      },
    }),
  ]);

  const recipientMap = new Map<string, Recipient>();

  // Assignees of the failed tasks.
  for (const t of tasks) {
    const user = t.assignee?.user;
    if (user?.id && user.email) recipientMap.set(user.id, toRecipient(user));
  }

  // Org admins/owners. member.role is a comma-separated list (e.g.
  // "admin,auditor"); match EXACT role tokens, not substrings, so a custom role
  // like "co-owner" or "billing-admin" is not mistaken for owner/admin.
  for (const member of allMembers) {
    const roles = (member.role ?? '').split(',').map((r) => r.trim());
    if (!roles.includes('admin') && !roles.includes('owner')) continue;
    const user = member.user;
    if (user?.id && user.email) recipientMap.set(user.id, toRecipient(user));
  }

  return Array.from(recipientMap.values());
}

/**
 * Send ONE bundled email per recipient listing every task currently failing,
 * replacing the previous one-email-per-failing-task spam. Exported for testing.
 */
export async function sendBundledFailureEmails(params: {
  organizationId: string;
  organizationName: string;
  failedTasks: FailedTaskSummary[];
}): Promise<void> {
  const { organizationId, organizationName, failedTasks } = params;
  if (failedTasks.length === 0) return;

  // The email is best-effort: a failure here (e.g. a transient DB blip while
  // resolving recipients) must NOT throw out of the runner, which would fail it
  // and retry the WHOLE org's checks. Mirrors the old per-task email's outer
  // try/catch guard.
  try {
    const appUrl =
      process.env.NEXT_PUBLIC_APP_URL ||
      process.env.BETTER_AUTH_URL ||
      'https://app.trycomp.ai';
    const tasksUrl = `${appUrl}/${organizationId}/tasks`;

    const recipients = await resolveRecipients({
      organizationId,
      failedTaskIds: failedTasks.map((t) => t.taskId),
    });

    const taskItems = failedTasks.map((t) => ({
      title: t.taskTitle,
      url: `${appUrl}/${organizationId}/tasks/${t.taskId}`,
      failedCount: t.failedCount,
      totalCount: t.totalCount,
    }));

    const count = failedTasks.length;
    const taskText = count === 1 ? 'task' : 'tasks';

    await Promise.allSettled(
      recipients.map(async (recipient) => {
        const isUnsubscribed = await isUserUnsubscribed(
          db,
          recipient.email,
          'taskAssignments',
          organizationId,
        );
        if (isUnsubscribed) {
          logger.info(
            `Skipping bundled failure email: ${recipient.email} is unsubscribed`,
          );
          return;
        }

        try {
          await triggerEmail({
            to: recipient.email,
            subject: `${count} ${taskText} failed automated checks in ${organizationName}`,
            react: AutomationBulkFailuresEmail({
              toName: recipient.name,
              toEmail: recipient.email,
              organizationName,
              tasksUrl,
              tasks: taskItems,
            }),
            system: true,
          });
          logger.info(`Bundled failure email sent to ${recipient.email}`);
        } catch (error) {
          logger.error(
            `Failed to send bundled failure email to ${recipient.email}`,
            { error: error instanceof Error ? error.message : 'Unknown error' },
          );
        }
      }),
    );

    logger.info(
      `Sent bundled failure email for ${count} ${taskText} to ${recipients.length} recipient(s) in org ${organizationId}`,
    );
  } catch (error) {
    logger.error('Failed to send bundled failure email(s)', {
      organizationId,
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
}
