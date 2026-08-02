import {
  Body,
  Controller,
  Get,
  HttpException,
  HttpStatus,
  Logger,
  Post,
  Query,
  Req,
  Res,
  UseGuards,
} from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';
import type { Request, Response } from 'express';
import { getManifest } from '@trycompai/integration-platform';
import { OrganizationId, UserId } from '../../auth/auth-context.decorator';
import { HybridAuthGuard } from '../../auth/hybrid-auth.guard';
import { PermissionGuard } from '../../auth/permission.guard';
import { RequirePermission } from '../../auth/require-permission.decorator';
import { SessionOnlyGuard } from '../../auth/session-only.guard';
import { ConnectionRepository } from '../repositories/connection.repository';
import { OAuthStateRepository } from '../repositories/oauth-state.repository';
import { ProviderRepository } from '../repositories/provider.repository';
import { AutoCheckRunnerService } from '../services/auto-check-runner.service';
import { ConnectionService } from '../services/connection.service';
import { CredentialVaultService } from '../services/credential-vault.service';
import { GithubAppTokenService } from '../services/github-app-token.service';
import { OAuthCallbackSupportService } from '../services/oauth-callback-support.service';

// Body DTOs are classes with class-validator decorators so the global
// ValidationPipe (whitelist: true) actually strips and validates them; a bare
// interface would be erased at runtime and silently validate nothing.
export class StartGitHubAppInstallDto {
  @IsOptional()
  @IsString()
  providerSlug?: string;

  @IsOptional()
  @IsString()
  redirectUrl?: string;
}

interface GitHubAppCallbackQuery {
  installation_id?: string;
  setup_action?: string;
  state?: string;
}

/**
 * Connect GitHub by installing a GitHub App on an organization.
 *
 * The flow differs from OAuth in a way that matters: there is no code to
 * exchange. GitHub redirects back with an `installation_id`, and that ID plus
 * the app's private key is the durable credential. Access is scoped to the
 * repositories the org granted the installation, so it does not depend on the
 * connecting user's own repository access or on them being an org owner.
 */
@ApiTags('Integrations')
@Controller({ path: 'integrations/github-app', version: '1' })
export class GitHubAppController {
  private readonly logger = new Logger(GitHubAppController.name);

  constructor(
    private readonly oauthStateRepository: OAuthStateRepository,
    private readonly providerRepository: ProviderRepository,
    private readonly connectionRepository: ConnectionRepository,
    private readonly connectionService: ConnectionService,
    private readonly credentialVaultService: CredentialVaultService,
    private readonly githubAppTokenService: GithubAppTokenService,
    private readonly callbackSupport: OAuthCallbackSupportService,
    private readonly autoCheckRunnerService: AutoCheckRunnerService,
  ) {}

  @Post('install')
  @ApiOperation({ summary: 'Start a GitHub App installation flow' })
  // SessionOnlyGuard mirrors the OAuth start endpoint: the callback requires a
  // real session, so an API-key or service-token caller could never finish.
  @UseGuards(HybridAuthGuard, SessionOnlyGuard, PermissionGuard)
  @RequirePermission('integration', 'create')
  async startInstall(
    @OrganizationId() organizationId: string,
    @UserId() userId: string,
    @Body() body: StartGitHubAppInstallDto,
  ): Promise<{ installationUrl: string }> {
    const providerSlug = body.providerSlug ?? 'github-app';
    const manifest = getManifest(providerSlug);

    if (!manifest) {
      throw new HttpException(
        `Provider ${providerSlug} not found`,
        HttpStatus.NOT_FOUND,
      );
    }

    if (manifest.auth.type !== 'github_app') {
      throw new HttpException(
        `Provider ${providerSlug} is not a GitHub App integration`,
        HttpStatus.BAD_REQUEST,
      );
    }

    const credentials = await this.githubAppTokenService.getCredentials(
      providerSlug,
      organizationId,
    );

    if (!credentials?.appSlug) {
      throw new HttpException(
        {
          message: `No GitHub App is configured for ${providerSlug}`,
          setupInstructions: manifest.auth.config.setupInstructions,
          createAppUrl: manifest.auth.config.createAppUrl,
        },
        HttpStatus.PRECONDITION_FAILED,
      );
    }

    await this.providerRepository.upsert({
      slug: manifest.id,
      name: manifest.name,
      category: manifest.category,
      capabilities: manifest.capabilities,
      isActive: manifest.isActive,
    });

    const state = await this.oauthStateRepository.create({
      providerSlug,
      organizationId,
      userId,
      redirectUrl: body.redirectUrl,
    });

    const installationUrl = await this.githubAppTokenService.getInstallUrl(
      providerSlug,
      organizationId,
      state.state,
    );

    if (!installationUrl) {
      throw new HttpException(
        'Could not build the GitHub App installation URL',
        HttpStatus.INTERNAL_SERVER_ERROR,
      );
    }

    this.logger.log(
      `Starting GitHub App install for ${providerSlug}, org: ${organizationId}`,
    );

    return { installationUrl };
  }

  /**
   * Installation callback. Deliberately unguarded so GitHub can redirect the
   * browser here; the state token and session match are validated below.
   */
  @Get('callback')
  @ApiOperation({ summary: 'Handle the GitHub App installation callback' })
  async installCallback(
    @Query() query: GitHubAppCallbackQuery,
    @Req() req: Request,
    @Res() res: Response,
  ): Promise<void> {
    const { installation_id: installationId, setup_action: setupAction } = query;
    const state = query.state;

    if (!state) {
      res.redirect(
        this.callbackSupport.buildRedirectUrl(null, {
          error: 'missing_state',
          error_description: 'The installation response was missing its state.',
        }),
      );
      return;
    }

    const flowState = await this.oauthStateRepository.findByState(state);
    if (!flowState || flowState.expiresAt < new Date()) {
      res.redirect(
        this.callbackSupport.buildRedirectUrl(null, {
          error: 'invalid_state',
          error_description:
            'The installation link has expired. Please start again.',
        }),
      );
      return;
    }

    const mismatch = await this.callbackSupport.checkSessionMatchesState(
      req,
      flowState,
    );
    if (mismatch) {
      await this.oauthStateRepository.delete(state);
      res.redirect(
        this.callbackSupport.buildRedirectUrl(
          flowState.redirectUrl,
          { error: mismatch.reason, error_description: mismatch.message },
          flowState.organizationId,
        ),
      );
      return;
    }

    // A user can land here having cancelled, or having only *requested* the
    // install when they lack permission to approve it on the org.
    if (!installationId) {
      await this.oauthStateRepository.delete(state);
      const requested = setupAction === 'request';
      res.redirect(
        this.callbackSupport.buildRedirectUrl(
          flowState.redirectUrl,
          {
            error: requested ? 'install_requires_approval' : 'install_cancelled',
            error_description: requested
              ? 'An organization owner must approve the GitHub App installation before it can be connected.'
              : 'The GitHub App installation was not completed.',
          },
          flowState.organizationId,
        ),
      );
      return;
    }

    try {
      const provider = await this.providerRepository.findBySlug(
        flowState.providerSlug,
      );
      if (!provider) {
        throw new Error(`Provider not found: ${flowState.providerSlug}`);
      }

      let connection = await this.connectionRepository.findByProviderAndOrg(
        provider.id,
        flowState.organizationId,
      );

      if (!connection) {
        connection = await this.connectionService.createConnection({
          providerSlug: provider.slug,
          organizationId: flowState.organizationId,
          authStrategy: 'github_app',
        });
      }

      // The installation ID is the whole credential on our side; the private key
      // that turns it into an access token is held once per app, not per
      // connection.
      await this.credentialVaultService.storeApiKeyCredentials(connection.id, {
        installation_id: installationId,
      });

      // A reinstall issues a new installation ID, so drop any token cached
      // against the previous one.
      this.githubAppTokenService.invalidate(connection.id);

      await this.connectionService.activateConnection(connection.id);
      await this.oauthStateRepository.delete(state);

      this.logger.log(
        `GitHub App installed for org ${flowState.organizationId} (installation ${installationId})`,
      );

      this.autoCheckRunnerService
        .tryAutoRunChecks(connection.id)
        .catch((err) =>
          this.logger.error(`Auto-run checks failed after install: ${err}`),
        );

      res.redirect(
        this.callbackSupport.buildRedirectUrl(
          flowState.redirectUrl,
          { success: 'true', provider: flowState.providerSlug },
          flowState.organizationId,
        ),
      );
    } catch (err) {
      this.logger.error(`GitHub App callback error: ${err}`);
      await this.oauthStateRepository.delete(state);

      res.redirect(
        this.callbackSupport.buildRedirectUrl(
          flowState.redirectUrl,
          {
            error: 'installation_failed',
            error_description:
              err instanceof Error
                ? err.message
                : 'Failed to complete the GitHub App installation',
          },
          flowState.organizationId,
        ),
      );
    }
  }
}
