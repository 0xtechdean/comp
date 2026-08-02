/**
 * GitHub App Integration Manifest
 *
 * Same compliance checks as the OAuth `github` integration, but authenticated
 * as a GitHub App installation instead of as a user.
 *
 * The distinction matters operationally. An OAuth grant belongs to the person
 * who clicked Authorize: it dies when they revoke it or leave the org, and it
 * can only see what that person can see — so a non-owner connecting silently
 * loses every private repository. An installation belongs to the organization
 * and is granted repositories explicitly, so private repos stay visible and no
 * individual's account is a single point of failure.
 *
 * The checks are imported unchanged from the OAuth manifest. Their repository
 * discovery tries `/installation/repositories` before the user-scoped
 * endpoints, so the same code serves both auth strategies.
 */

import type { IntegrationManifest } from '../../types';
import { branchProtectionCheck } from '../github/checks/branch-protection';
import { codeScanningCheck } from '../github/checks/code-scanning';
import { dependabotCheck } from '../github/checks/dependabot';
import { sanitizedInputsCheck } from '../github/checks/sanitized-inputs';
import { twoFactorAuthCheck } from '../github/checks/two-factor-auth';

export const manifest: IntegrationManifest = {
  id: 'github-app',
  name: 'GitHub (App)',
  description:
    'Connect GitHub via a GitHub App installation to monitor repository security, branch protection, and organization settings. Recommended over the OAuth integration: access is owned by the organization rather than by one user.',
  category: 'Development',
  logoUrl: 'https://img.logo.dev/github.com?token=pk_AZatYxV5QDSfWpRDaBxzRQ',
  docsUrl: 'https://docs.trycomp.ai/integrations/github',

  // API configuration for ctx.fetch helper
  baseUrl: 'https://api.github.com',
  defaultHeaders: {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'CompAI-Integration',
    'X-GitHub-Api-Version': '2022-11-28',
  },

  auth: {
    type: 'github_app',
    config: {
      apiBaseUrl: 'https://api.github.com',
      installUrl: 'https://github.com/apps/{APP_SLUG}/installations/new',
      installationTokenUrl:
        'https://api.github.com/app/installations/{INSTALLATION_ID}/access_tokens',
      tokenRefreshLeewaySeconds: 300,
      appJwtExpirySeconds: 540,
      repositoryPermissions: {
        // `/repos/{owner}/{repo}` — repository existence and default branch
        metadata: 'read',
        // `/repos/{r}/git/trees` and `/repos/{r}/contents` — workflow scanning
        contents: 'read',
        // Branch protection rules and Dependabot security-update settings
        administration: 'read',
        // `/repos/{r}/pulls` — review policy evidence
        pull_requests: 'read',
        // `/repos/{r}/dependabot/alerts`
        vulnerability_alerts: 'read',
        // `/repos/{r}/code-scanning/default-setup`
        security_events: 'read',
      },
      organizationPermissions: {
        // `/orgs/{org}/members`
        members: 'read',
        // `/orgs/{org}` — the two_factor_requirement_enabled flag
        administration: 'read',
      },
      setupInstructions: [
        'Create a GitHub App under your organization (Settings > Developer settings > GitHub Apps).',
        'Grant the repository permissions Metadata, Contents, Administration, Pull requests, Dependabot alerts and Code scanning alerts as read-only.',
        'Grant the organization permissions Members and Administration as read-only.',
        'Generate a private key and record the App ID and the app slug from its public page URL.',
        'Install the app on your organization and grant it the repositories you want monitored.',
      ].join('\n'),
      createAppUrl: 'https://github.com/settings/apps/new',
      additionalSettings: [
        {
          id: 'appSlug',
          label: 'App slug',
          type: 'text',
          required: true,
          placeholder: 'comp-ai-compliance',
          helpText:
            "The app's URL name, taken from https://github.com/apps/<slug>. Used to build the installation link.",
        },
      ],
    },
  },

  capabilities: ['checks'],

  services: [
    {
      id: 'code-security',
      name: 'Code Security',
      description: 'Branch protection and code review policies',
      enabledByDefault: true,
      implemented: true,
    },
    {
      id: 'dependency-management',
      name: 'Dependency Management',
      description: 'Automated dependency updates and vulnerability scanning',
      enabledByDefault: true,
      implemented: true,
    },
  ],

  checks: [
    branchProtectionCheck,
    codeScanningCheck,
    dependabotCheck,
    sanitizedInputsCheck,
    twoFactorAuthCheck,
  ],

  isActive: true,
};

export default manifest;
