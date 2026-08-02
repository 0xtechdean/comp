// Mock @db so importing the services doesn't open a Postgres connection.
jest.mock('@db', () => ({ db: {} }));

import { Test } from '@nestjs/testing';
import {
  githubAppManifest,
  githubManifest,
  type IntegrationManifest,
} from '@trycompai/integration-platform';
import { ConnectionAuthResolverService } from './connection-auth-resolver.service';
import { CredentialVaultService } from './credential-vault.service';
import { GithubAppTokenService } from './github-app-token.service';
import { OAuthCredentialsService } from './oauth-credentials.service';

const ORG = 'org_test';
const CONNECTION = 'icn_test';

const oauthCredentialsService = { getCredentials: jest.fn() };
const credentialVaultService = {
  getValidAccessToken: jest.fn(),
  refreshOAuthTokens: jest.fn(),
};
const githubAppTokenService = {
  getInstallationToken: jest.fn(),
  invalidate: jest.fn(),
};

describe('ConnectionAuthResolverService', () => {
  let service: ConnectionAuthResolverService;

  beforeEach(async () => {
    jest.clearAllMocks();

    const moduleRef = await Test.createTestingModule({
      providers: [
        ConnectionAuthResolverService,
        { provide: OAuthCredentialsService, useValue: oauthCredentialsService },
        { provide: CredentialVaultService, useValue: credentialVaultService },
        { provide: GithubAppTokenService, useValue: githubAppTokenService },
      ],
    }).compile();

    service = moduleRef.get(ConnectionAuthResolverService);
  });

  describe('github_app', () => {
    const resolveGitHubApp = (
      credentials: Record<string, string | string[]>,
    ) =>
      service.resolve({
        manifest: githubAppManifest,
        providerSlug: 'github-app',
        organizationId: ORG,
        connectionId: CONNECTION,
        credentials,
      });

    it('mints an installation token from the stored installation id', async () => {
      githubAppTokenService.getInstallationToken.mockResolvedValue('ghs_tok');

      const result = await resolveGitHubApp({ installation_id: '4242' });

      expect(result.accessToken).toBe('ghs_tok');
      expect(githubAppTokenService.getInstallationToken).toHaveBeenCalledWith({
        providerSlug: 'github-app',
        organizationId: ORG,
        connectionId: CONNECTION,
        installationId: '4242',
      });
    });

    it('onTokenRefresh forces a re-mint so an expired token recovers mid-run', async () => {
      githubAppTokenService.getInstallationToken.mockResolvedValue('ghs_fresh');

      const { onTokenRefresh } = await resolveGitHubApp({
        installation_id: '4242',
      });
      const refreshed = await onTokenRefresh?.();

      expect(refreshed).toBe('ghs_fresh');
      expect(githubAppTokenService.getInstallationToken).toHaveBeenLastCalledWith(
        expect.objectContaining({ forceRefresh: true }),
      );
    });

    it('yields no token when the connection has no installation id', async () => {
      const result = await resolveGitHubApp({});

      expect(result.accessToken).toBeUndefined();
      expect(result.onTokenRefresh).toBeUndefined();
      expect(githubAppTokenService.getInstallationToken).not.toHaveBeenCalled();
    });

    it('yields no token when minting fails, rather than a bogus one', async () => {
      githubAppTokenService.getInstallationToken.mockResolvedValue(null);

      const result = await resolveGitHubApp({ installation_id: '4242' });

      expect(result.accessToken).toBeUndefined();
    });
  });

  describe('oauth2', () => {
    const resolveOAuth = () =>
      service.resolve({
        manifest: githubManifest,
        providerSlug: 'github',
        organizationId: ORG,
        connectionId: CONNECTION,
        credentials: { access_token: 'gho_stored' },
      });

    it('passes the stored token through when the provider cannot refresh', async () => {
      // The GitHub OAuth manifest sets supportsRefreshToken: false — its tokens
      // are valid until revoked, so there is nothing to refresh.
      const result = await resolveOAuth();

      expect(result.accessToken).toBe('gho_stored');
      expect(result.onTokenRefresh).toBeUndefined();
      expect(oauthCredentialsService.getCredentials).not.toHaveBeenCalled();
    });

    it('prefers a refreshed token for providers that support refresh', async () => {
      if (githubManifest.auth.type !== 'oauth2') {
        throw new Error('Fixture changed: expected the GitHub manifest to be oauth2');
      }

      const refreshable: IntegrationManifest = {
        ...githubManifest,
        auth: {
          type: 'oauth2',
          config: { ...githubManifest.auth.config, supportsRefreshToken: true },
        },
      };
      oauthCredentialsService.getCredentials.mockResolvedValue({
        clientId: 'id',
        clientSecret: 'secret',
        scopes: ['repo'],
        source: 'platform',
      });
      credentialVaultService.getValidAccessToken.mockResolvedValue('gho_fresh');

      const result = await service.resolve({
        manifest: refreshable,
        providerSlug: 'github',
        organizationId: ORG,
        connectionId: CONNECTION,
        credentials: { access_token: 'gho_stored' },
      });

      expect(result.accessToken).toBe('gho_fresh');
      expect(result.onTokenRefresh).toBeDefined();
    });
  });

  it('falls back to the raw stored credential for other strategies', async () => {
    const apiKeyManifest: IntegrationManifest = {
      ...githubManifest,
      auth: {
        type: 'api_key',
        config: { in: 'header', name: 'X-Api-Key' },
      },
    };

    const result = await service.resolve({
      manifest: apiKeyManifest,
      providerSlug: 'whatever',
      organizationId: ORG,
      connectionId: CONNECTION,
      credentials: { access_token: 'raw_token' },
    });

    expect(result.accessToken).toBe('raw_token');
    expect(result.onTokenRefresh).toBeUndefined();
  });
});
