import { Injectable, Logger } from '@nestjs/common';
import type { IntegrationManifest } from '@trycompai/integration-platform';
import { getStringValue } from '../utils/credential-utils';
import { CredentialVaultService } from './credential-vault.service';
import { GithubAppTokenService } from './github-app-token.service';
import { OAuthCredentialsService } from './oauth-credentials.service';

export interface ResolvedConnectionAuth {
  /** Bearer token to run checks with, if the strategy uses one. */
  accessToken: string | undefined;
  /** Invoked by the check runtime when a request comes back 401. */
  onTokenRefresh?: () => Promise<string | null>;
}

export interface ResolveConnectionAuthInput {
  manifest: IntegrationManifest;
  providerSlug: string;
  organizationId: string;
  connectionId: string;
  credentials: Record<string, string | string[]>;
}

/**
 * Resolves the credential a check run should execute with.
 *
 * This logic used to be copy-pasted across the check controllers and the
 * Trigger tasks, which meant a new auth strategy had to be added in four
 * places and could silently work in some entry points but not others.
 */
@Injectable()
export class ConnectionAuthResolverService {
  private readonly logger = new Logger(ConnectionAuthResolverService.name);

  constructor(
    private readonly oauthCredentialsService: OAuthCredentialsService,
    private readonly credentialVaultService: CredentialVaultService,
    private readonly githubAppTokenService: GithubAppTokenService,
  ) {}

  async resolve({
    manifest,
    providerSlug,
    organizationId,
    connectionId,
    credentials,
  }: ResolveConnectionAuthInput): Promise<ResolvedConnectionAuth> {
    if (manifest.auth.type === 'oauth2') {
      return this.resolveOAuth({
        manifest,
        providerSlug,
        organizationId,
        connectionId,
        credentials,
      });
    }

    if (manifest.auth.type === 'github_app') {
      return this.resolveGitHubApp({
        providerSlug,
        organizationId,
        connectionId,
        credentials,
      });
    }

    return { accessToken: getStringValue(credentials.access_token) };
  }

  private async resolveOAuth({
    manifest,
    providerSlug,
    organizationId,
    connectionId,
    credentials,
  }: ResolveConnectionAuthInput): Promise<ResolvedConnectionAuth> {
    const accessToken = getStringValue(credentials.access_token);
    if (manifest.auth.type !== 'oauth2') return { accessToken };

    const oauthConfig = manifest.auth.config;
    if (oauthConfig.supportsRefreshToken === false) return { accessToken };

    const oauthCredentials = await this.oauthCredentialsService.getCredentials(
      providerSlug,
      organizationId,
    );
    if (!oauthCredentials) return { accessToken };

    const refreshConfig = {
      tokenUrl: oauthConfig.tokenUrl,
      refreshUrl: oauthConfig.refreshUrl,
      clientId: oauthCredentials.clientId,
      clientSecret: oauthCredentials.clientSecret,
      clientAuthMethod: oauthConfig.clientAuthMethod,
      scope: oauthCredentials.scopes.join(' '),
      tokenParams: oauthConfig.tokenParams,
    };

    const validAccessToken =
      await this.credentialVaultService.getValidAccessToken(
        connectionId,
        refreshConfig,
      );

    return {
      accessToken: validAccessToken ?? accessToken,
      onTokenRefresh: () =>
        this.credentialVaultService.refreshOAuthTokens(
          connectionId,
          refreshConfig,
        ),
    };
  }

  /**
   * GitHub App installation tokens expire after an hour, so one is minted for
   * every run rather than read from storage. The refresh hook forces a re-mint,
   * which covers both natural expiry mid-run and an installation whose
   * permissions changed underneath us.
   */
  private async resolveGitHubApp({
    providerSlug,
    organizationId,
    connectionId,
    credentials,
  }: Omit<ResolveConnectionAuthInput, 'manifest'>): Promise<ResolvedConnectionAuth> {
    const installationId = getStringValue(credentials.installation_id);
    if (!installationId) {
      this.logger.error(
        `Connection ${connectionId} has no installation_id; reconnect the GitHub App`,
      );
      return { accessToken: undefined };
    }

    const request = {
      providerSlug,
      organizationId,
      connectionId,
      installationId,
    };

    const accessToken =
      await this.githubAppTokenService.getInstallationToken(request);

    return {
      accessToken: accessToken ?? undefined,
      onTokenRefresh: () =>
        this.githubAppTokenService.getInstallationToken({
          ...request,
          forceRefresh: true,
        }),
    };
  }
}
