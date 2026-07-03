import type { IntegrationCheck } from '../../../types';
import { ACCOUNT_QUERY, RAILWAY_GRAPHQL_ENDPOINT } from '../queries';
import type { RailwayViewer } from '../types';

/**
 * Railway Account 2FA Check
 *
 * Verifies the Railway account behind the connected token has a strong second
 * factor (TOTP/SMS or a passkey). A privileged Railway account without MFA is a
 * standing account-takeover risk for everything the workspace deploys.
 */
export const accountTwoFactorCheck: IntegrationCheck = {
  id: 'railway-account-2fa',
  name: 'Railway account has two-factor authentication',
  description:
    'Checks that the connected Railway account has 2FA or a passkey enrolled.',
  defaultSeverity: 'high',
  service: 'access',

  run: async (ctx) => {
    ctx.log('Fetching Railway account MFA status');
    const { me } = await ctx.graphql<{ me: RailwayViewer }>(
      ACCOUNT_QUERY,
      undefined,
      { endpoint: RAILWAY_GRAPHQL_ENDPOINT },
    );

    const label = me.email || me.name || me.id;
    const hasStrongFactor = Boolean(me.has2FA || me.hasPasskeys);
    const evidence = {
      serviceId: 'access',
      findingKey: 'railway-account-2fa',
      account: label,
      has2FA: me.has2FA,
      hasPasskeys: me.hasPasskeys,
      checkedAt: new Date().toISOString(),
    };

    if (hasStrongFactor) {
      ctx.pass({
        title: `Two-factor authentication enabled for ${label}`,
        description:
          'The connected Railway account has a second factor (2FA or passkey) enrolled.',
        resourceType: 'railway-account',
        resourceId: me.id,
        evidence,
      });
      return;
    }

    ctx.fail({
      title: `Railway account ${label} has no two-factor authentication`,
      description:
        'The connected Railway account can be accessed with a password alone, leaving every ' +
        'project and deployment it controls exposed to account takeover.',
      resourceType: 'railway-account',
      resourceId: me.id,
      severity: 'high',
      remediation:
        'Enable 2FA at https://railway.com/account/security (add an authenticator app or a passkey), then re-run this check.',
      evidence,
    });
  },
};
