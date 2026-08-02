import { Injectable, Logger } from '@nestjs/common';
import { createSign } from 'node:crypto';
import {
  getManifest,
  type GitHubAppConfig,
} from '@trycompai/integration-platform';
import { OAuthAppRepository } from '../repositories/oauth-app.repository';
import { PlatformCredentialRepository } from '../repositories/platform-credential.repository';
import {
  CredentialVaultService,
  EncryptedData,
} from './credential-vault.service';

/**
 * Credentials identifying the GitHub App itself (not any one installation).
 *
 * These reuse the OAuth credential tables rather than adding new ones: the app
 * ID takes the client-ID slot and the PEM private key takes the client-secret
 * slot. Both are already encrypted at rest by the same vault, so a GitHub App
 * needs no schema migration.
 */
export interface GitHubAppCredentials {
  appId: string;
  privateKey: string;
  appSlug?: string;
  source: 'organization' | 'platform';
}

interface CachedToken {
  token: string;
  /** Absolute expiry reported by GitHub, in epoch milliseconds. */
  expiresAtMs: number;
}

interface InstallationTokenResponse {
  token: string;
  expires_at: string;
}

const isInstallationTokenResponse = (
  value: unknown,
): value is InstallationTokenResponse => {
  if (typeof value !== 'object' || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return (
    typeof candidate.token === 'string' &&
    typeof candidate.expires_at === 'string'
  );
};

/**
 * Coerce a pasted private key back into a PEM OpenSSL will accept.
 *
 * Keys reach us through env vars, JSON and web forms, any of which can turn the
 * line breaks into literal `\n`, CRLF, or nothing at all. OpenSSL rejects all
 * three with an opaque "DECODER routines::unsupported", so normalise here
 * rather than making every operator debug it.
 */
export const normalizePrivateKey = (raw: string): string => {
  const unescaped = raw
    .trim()
    .replace(/\\r\\n|\\n/g, '\n')
    .replace(/\r\n?/g, '\n');

  // Already has real line breaks in the body — nothing to rebuild.
  if (unescaped.includes('\n')) return unescaped;

  // Single-line paste: the base64 body must be re-wrapped at 64 columns, since
  // PEM is only valid as a line-broken block.
  const match = unescaped.match(
    /^-----BEGIN ([A-Z0-9 ]+)-----\s*(.*?)\s*-----END \1-----$/,
  );
  if (!match) return unescaped;

  const [, label, body] = match;
  const wrapped = body.replace(/\s+/g, '').match(/.{1,64}/g)?.join('\n');
  if (!wrapped) return unescaped;

  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----\n`;
};

/** Shape of a key, safe to log — never includes key material. */
const describeKey = (key: string): string => {
  const firstLine = key.split('\n')[0]?.slice(0, 40) ?? '';
  return `length=${key.length} lines=${key.split('\n').length} startsWith="${firstLine}"`;
};

const base64Url = (input: Buffer | string): string =>
  (typeof input === 'string' ? Buffer.from(input) : input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');

/**
 * Mints short-lived GitHub App installation access tokens.
 *
 * An installation token is scoped to the repositories the org granted the app,
 * which is why this survives the failure mode OAuth has: it does not depend on
 * one user's grant, and it reaches private repos without the connecting user
 * being an org owner. Tokens last one hour, so they are cached in-process and
 * re-minted just before expiry (or on demand after a 401).
 */
@Injectable()
export class GithubAppTokenService {
  private readonly logger = new Logger(GithubAppTokenService.name);
  private readonly tokenCache = new Map<string, CachedToken>();

  constructor(
    private readonly oauthAppRepository: OAuthAppRepository,
    private readonly platformCredentialRepository: PlatformCredentialRepository,
    private readonly credentialVaultService: CredentialVaultService,
  ) {}

  getConfig(providerSlug: string): GitHubAppConfig | null {
    const manifest = getManifest(providerSlug);
    if (!manifest || manifest.auth.type !== 'github_app') return null;
    return manifest.auth.config;
  }

  /**
   * Resolve the app's own credentials, preferring org-level over platform-level
   * so a self-hosted instance can point at its own GitHub App.
   */
  async getCredentials(
    providerSlug: string,
    organizationId: string,
  ): Promise<GitHubAppCredentials | null> {
    if (!this.getConfig(providerSlug)) return null;

    const orgApp = await this.oauthAppRepository.findActiveByProviderAndOrg(
      providerSlug,
      organizationId,
    );
    if (orgApp) {
      const decoded = await this.decodeCredentials(
        orgApp.encryptedClientId,
        orgApp.encryptedClientSecret,
        orgApp.customSettings,
        'organization',
      );
      if (decoded) return decoded;
    }

    const platformApp =
      await this.platformCredentialRepository.findActiveByProviderSlug(
        providerSlug,
      );
    if (platformApp) {
      const decoded = await this.decodeCredentials(
        platformApp.encryptedClientId,
        platformApp.encryptedClientSecret,
        platformApp.customSettings,
        'platform',
      );
      if (decoded) return decoded;
    }

    return null;
  }

  private async decodeCredentials(
    encryptedAppId: unknown,
    encryptedPrivateKey: unknown,
    customSettings: unknown,
    source: 'organization' | 'platform',
  ): Promise<GitHubAppCredentials | null> {
    try {
      const appId = await this.credentialVaultService.decrypt(
        encryptedAppId as EncryptedData,
      );
      const privateKey = await this.credentialVaultService.decrypt(
        encryptedPrivateKey as EncryptedData,
      );
      return {
        appId,
        privateKey: normalizePrivateKey(privateKey),
        appSlug: this.readAppSlug(customSettings),
        source,
      };
    } catch (error) {
      this.logger.error(
        `Failed to decrypt GitHub App credentials (${source}): ${error}`,
      );
      return null;
    }
  }

  private readAppSlug(customSettings: unknown): string | undefined {
    if (typeof customSettings !== 'object' || customSettings === null) {
      return undefined;
    }
    const slug = (customSettings as Record<string, unknown>).appSlug;
    return typeof slug === 'string' && slug.length > 0 ? slug : undefined;
  }

  /**
   * Build the URL an org owner visits to install the app.
   */
  async getInstallUrl(
    providerSlug: string,
    organizationId: string,
    state: string,
  ): Promise<string | null> {
    const config = this.getConfig(providerSlug);
    const credentials = await this.getCredentials(providerSlug, organizationId);
    if (!config || !credentials?.appSlug) return null;

    const base = config.installUrl.replace('{APP_SLUG}', credentials.appSlug);
    const url = new URL(base);
    url.searchParams.set('state', state);
    return url.toString();
  }

  /**
   * Get a usable installation token, minting a fresh one when the cached token
   * is missing, near expiry, or explicitly invalidated by a 401.
   */
  async getInstallationToken({
    providerSlug,
    organizationId,
    connectionId,
    installationId,
    forceRefresh = false,
  }: {
    providerSlug: string;
    organizationId: string;
    connectionId: string;
    installationId: string;
    forceRefresh?: boolean;
  }): Promise<string | null> {
    const config = this.getConfig(providerSlug);
    if (!config) return null;

    const leewayMs = config.tokenRefreshLeewaySeconds * 1000;
    const cached = this.tokenCache.get(connectionId);
    if (!forceRefresh && cached && cached.expiresAtMs - leewayMs > Date.now()) {
      return cached.token;
    }

    const credentials = await this.getCredentials(providerSlug, organizationId);
    if (!credentials) {
      this.logger.error(
        `No GitHub App credentials configured for provider ${providerSlug}`,
      );
      return null;
    }

    const minted = await this.mintInstallationToken({
      config,
      credentials,
      installationId,
    });
    if (!minted) return null;

    this.tokenCache.set(connectionId, minted);
    return minted.token;
  }

  private async mintInstallationToken({
    config,
    credentials,
    installationId,
  }: {
    config: GitHubAppConfig;
    credentials: GitHubAppCredentials;
    installationId: string;
  }): Promise<CachedToken | null> {
    let appJwt: string;
    try {
      appJwt = this.signAppJwt(credentials, config.appJwtExpirySeconds);
    } catch (error) {
      // Log the key's shape, never its contents — this is almost always a
      // malformed paste, and the raw OpenSSL error alone says nothing useful.
      this.logger.error(
        `Failed to sign GitHub App JWT (appId=${credentials.appId}, ${describeKey(credentials.privateKey)}): ${error}`,
      );
      return null;
    }

    const url = config.installationTokenUrl.replace(
      '{INSTALLATION_ID}',
      encodeURIComponent(installationId),
    );

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${appJwt}`,
        Accept: 'application/vnd.github+json',
        'User-Agent': 'CompAI-Integration',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    });

    if (!response.ok) {
      const body = await response.text().catch(() => '');
      this.logger.error(
        `Installation token request failed (${response.status}) for installation ${installationId}: ${body.slice(0, 300)}`,
      );
      return null;
    }

    const parsed: unknown = await response.json();
    if (!isInstallationTokenResponse(parsed)) {
      this.logger.error('Unexpected installation token response shape');
      return null;
    }

    return {
      token: parsed.token,
      expiresAtMs: new Date(parsed.expires_at).getTime(),
    };
  }

  /**
   * RS256-signed JWT proving app identity. GitHub rejects a JWT whose `iat` is
   * in its future, so back-date it to absorb clock skew between us and GitHub.
   */
  private signAppJwt(
    credentials: GitHubAppCredentials,
    expirySeconds: number,
  ): string {
    const nowSeconds = Math.floor(Date.now() / 1000);
    const header = base64Url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
    const payload = base64Url(
      JSON.stringify({
        iat: nowSeconds - 60,
        exp: nowSeconds + expirySeconds,
        iss: credentials.appId,
      }),
    );

    const signingInput = `${header}.${payload}`;
    const signature = createSign('RSA-SHA256')
      .update(signingInput)
      .sign(credentials.privateKey);

    return `${signingInput}.${base64Url(signature)}`;
  }

  /** Drop a cached token so the next request mints a fresh one. */
  invalidate(connectionId: string): void {
    this.tokenCache.delete(connectionId);
  }
}
