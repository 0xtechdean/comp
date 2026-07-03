import type { IntegrationCheck } from '../../../types';
import { RAILWAY_GRAPHQL_ENDPOINT, WORKSPACES_QUERY } from '../queries';
import type { RailwayWorkspace } from '../types';

/**
 * Railway Workspace 2FA Enforcement Check
 *
 * Two findings per workspace:
 *  - the workspace does not *enforce* 2FA on its members, and
 *  - one finding per member who has not enrolled in 2FA (`usersWithout2FA`).
 * Enforcement is what makes MFA a durable control rather than an opt-in.
 */
export const workspaceTwoFactorCheck: IntegrationCheck = {
  id: 'railway-workspace-2fa',
  name: 'Railway workspaces enforce two-factor authentication',
  description:
    'Checks that each Railway workspace enforces 2FA and that every member has enrolled.',
  defaultSeverity: 'high',
  service: 'access',

  run: async (ctx) => {
    ctx.log('Fetching Railway workspaces and 2FA enforcement');
    const { me } = await ctx.graphql<{ me: { workspaces: RailwayWorkspace[] } }>(
      WORKSPACES_QUERY,
      undefined,
      { endpoint: RAILWAY_GRAPHQL_ENDPOINT },
    );

    const workspaces = me.workspaces ?? [];
    ctx.log(`Checking ${workspaces.length} workspace(s)`);

    for (const ws of workspaces) {
      const usersWithout2FA = ws.usersWithout2FA ?? [];
      const baseEvidence = {
        serviceId: 'access',
        workspace: ws.name,
        workspaceId: ws.id,
        has2FAEnforcement: ws.has2FAEnforcement,
        hasSAML: ws.hasSAML,
        usersWithout2FA,
        checkedAt: new Date().toISOString(),
      };

      if (ws.has2FAEnforcement) {
        ctx.pass({
          title: `Workspace "${ws.name}" enforces two-factor authentication`,
          description:
            'Every member of this Railway workspace is required to enrol in 2FA.',
          resourceType: 'railway-workspace',
          resourceId: ws.id,
          evidence: { ...baseEvidence, findingKey: 'railway-workspace-2fa' },
        });
      } else {
        ctx.fail({
          title: `Workspace "${ws.name}" does not enforce two-factor authentication`,
          description:
            'Members can access this workspace without a second factor. Enforcement is what ' +
            'turns MFA into a guaranteed control instead of an opt-in each member may skip.',
          resourceType: 'railway-workspace',
          resourceId: ws.id,
          severity: 'high',
          remediation:
            'In Railway, open Workspace Settings → Security and turn on "Require two-factor authentication for all members".',
          evidence: { ...baseEvidence, findingKey: 'railway-workspace-2fa' },
        });
      }

      // One finding per member missing 2FA so each is tracked/remediated individually.
      for (const email of usersWithout2FA) {
        ctx.fail({
          title: `${email} has no two-factor authentication in "${ws.name}"`,
          description:
            `Workspace member ${email} has not enrolled a second factor and can be accessed with a password alone.`,
          resourceType: 'railway-workspace-member',
          resourceId: `${ws.id}:${email}`,
          severity: 'high',
          remediation:
            `Ask ${email} to enable 2FA at https://railway.com/account/security, or remove their access if the account is unused.`,
          evidence: {
            serviceId: 'access',
            findingKey: 'railway-member-2fa',
            workspace: ws.name,
            workspaceId: ws.id,
            member: email,
            checkedAt: new Date().toISOString(),
          },
        });
      }
    }
  },
};
