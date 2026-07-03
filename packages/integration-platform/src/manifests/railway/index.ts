import type { IntegrationManifest } from '../../types';
import {
  accountTwoFactorCheck,
  projectInventoryCheck,
  projectVisibilityCheck,
  workspaceTwoFactorCheck,
} from './checks';

/**
 * Railway — deployment PaaS. Connected with a read-only Railway account token,
 * Comp AI scans the workspace's security posture (account/workspace 2FA, public
 * project exposure) via the Railway GraphQL API and surfaces the results as Cloud
 * Security Tests alongside AWS/GCP/Azure.
 *
 * Auth: an API "account token" sent as `Authorization: Bearer <token>`. The token
 * is stored under `api_key` by the connect flow; the runtime reads it via the
 * api_key header strategy.
 */
export const railwayManifest: IntegrationManifest = {
  id: 'railway',
  name: 'Railway',
  description:
    'Scan your Railway workspace for security posture — account and workspace 2FA, public project exposure, and a project inventory.',
  category: 'Cloud',
  logoUrl:
    'https://img.logo.dev/railway.app?token=pk_AZatYxV5QDSfWpRDaBxzRQ&format=png&retina=true',
  docsUrl: 'https://docs.railway.com/reference/public-api',

  baseUrl: 'https://backboard.railway.com',
  defaultHeaders: {
    Accept: 'application/json',
  },

  auth: {
    type: 'api_key',
    config: { in: 'header', name: 'Authorization', prefix: 'Bearer ' },
  },
  credentialFields: [
    {
      id: 'api_key',
      label: 'Railway account token',
      type: 'password',
      required: true,
      placeholder: 'Paste your Railway account token',
      helpText:
        'Create an Account token at https://railway.com/account/tokens (leave the team field empty for full-account coverage). A read-only token is sufficient.',
    },
  ],

  capabilities: ['checks'],

  // Multiple Railway workspaces/teams can be connected separately, and this flag
  // is what the cloud-security orchestrator uses to pick up the connection for
  // its daily scan (same as AWS).
  supportsMultipleConnections: true,

  services: [
    {
      id: 'access',
      name: 'Access & MFA',
      description:
        'Account and workspace two-factor authentication enforcement.',
      enabledByDefault: true,
      implemented: true,
    },
    {
      id: 'exposure',
      name: 'Project Exposure',
      description: 'Public project visibility and project inventory.',
      enabledByDefault: true,
      implemented: true,
    },
  ],

  checks: [
    accountTwoFactorCheck,
    workspaceTwoFactorCheck,
    projectVisibilityCheck,
    projectInventoryCheck,
  ],

  isActive: true,
};

export default railwayManifest;
export * from './types';
