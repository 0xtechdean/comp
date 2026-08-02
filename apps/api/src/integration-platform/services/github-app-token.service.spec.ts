// Mock @db so importing the repositories doesn't open a Postgres connection.
jest.mock('@db', () => ({ db: {} }));

import { Test } from '@nestjs/testing';
import { createPrivateKey, createPublicKey, createVerify, generateKeyPairSync } from 'node:crypto';
import { GithubAppTokenService, normalizePrivateKey } from './github-app-token.service';
import { OAuthAppRepository } from '../repositories/oauth-app.repository';
import { PlatformCredentialRepository } from '../repositories/platform-credential.repository';
import { CredentialVaultService } from './credential-vault.service';

const { privateKey, publicKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

const PRIVATE_KEY_PEM = privateKey
  .export({ type: 'pkcs8', format: 'pem' })
  .toString();

const APP_ID = '123456';
const APP_SLUG = 'comp-ai-compliance';
const PROVIDER = 'github-app';
const ORG = 'org_test';
const CONNECTION = 'icn_test';
const INSTALLATION = '99887766';

const encrypted = (value: string) => ({ ciphertext: value, iv: 'iv', salt: 's' });

/** Decrypt stub: our fake "encryption" just echoes the ciphertext field. */
const decrypt = jest.fn(
  async (data: { ciphertext: string }) => data.ciphertext,
);

const oauthAppRepository = {
  findActiveByProviderAndOrg: jest.fn(),
};
const platformCredentialRepository = {
  findActiveByProviderSlug: jest.fn(),
};

const orgAppRow = {
  encryptedClientId: encrypted(APP_ID),
  encryptedClientSecret: encrypted(PRIVATE_KEY_PEM),
  customSettings: { appSlug: APP_SLUG },
};

const buildService = async (): Promise<GithubAppTokenService> => {
  const moduleRef = await Test.createTestingModule({
    providers: [
      GithubAppTokenService,
      { provide: OAuthAppRepository, useValue: oauthAppRepository },
      {
        provide: PlatformCredentialRepository,
        useValue: platformCredentialRepository,
      },
      { provide: CredentialVaultService, useValue: { decrypt } },
    ],
  }).compile();

  return moduleRef.get(GithubAppTokenService);
};

const mockTokenResponse = (token: string, expiresInMs: number) =>
  ({
    ok: true,
    status: 201,
    json: async () => ({
      token,
      expires_at: new Date(Date.now() + expiresInMs).toISOString(),
    }),
    text: async () => '',
  }) as unknown as Response;

describe('GithubAppTokenService', () => {
  let service: GithubAppTokenService;
  let fetchSpy: jest.SpiedFunction<typeof fetch>;

  beforeEach(async () => {
    jest.clearAllMocks();
    oauthAppRepository.findActiveByProviderAndOrg.mockResolvedValue(orgAppRow);
    platformCredentialRepository.findActiveByProviderSlug.mockResolvedValue(null);
    fetchSpy = jest.spyOn(global, 'fetch');
    service = await buildService();
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  const request = {
    providerSlug: PROVIDER,
    organizationId: ORG,
    connectionId: CONNECTION,
    installationId: INSTALLATION,
  };

  it('mints an installation token and targets the right installation', async () => {
    fetchSpy.mockResolvedValue(mockTokenResponse('ghs_minted', 3_600_000));

    const token = await service.getInstallationToken(request);

    expect(token).toBe('ghs_minted');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const [url, init] = fetchSpy.mock.calls[0];
    expect(String(url)).toBe(
      `https://api.github.com/app/installations/${INSTALLATION}/access_tokens`,
    );
    expect(init?.method).toBe('POST');
  });

  it('signs the app JWT with RS256 so GitHub can verify it against the app public key', async () => {
    fetchSpy.mockResolvedValue(mockTokenResponse('ghs_minted', 3_600_000));

    await service.getInstallationToken(request);

    const [, init] = fetchSpy.mock.calls[0];
    const headers = init?.headers as Record<string, string>;
    const jwt = headers.Authorization.replace('Bearer ', '');
    const [header, payload, signature] = jwt.split('.');

    const decodedHeader = JSON.parse(
      Buffer.from(header, 'base64url').toString(),
    );
    const decodedPayload = JSON.parse(
      Buffer.from(payload, 'base64url').toString(),
    );

    expect(decodedHeader).toEqual({ alg: 'RS256', typ: 'JWT' });
    expect(decodedPayload.iss).toBe(APP_ID);
    // Back-dated to absorb clock skew — GitHub rejects a future `iat`.
    expect(decodedPayload.iat).toBeLessThan(Math.floor(Date.now() / 1000));
    // GitHub rejects any JWT living longer than 10 minutes.
    expect(decodedPayload.exp - decodedPayload.iat).toBeLessThanOrEqual(600);

    const verified = createVerify('RSA-SHA256')
      .update(`${header}.${payload}`)
      .verify(
        createPublicKey(publicKey.export({ type: 'spki', format: 'pem' })),
        Buffer.from(signature, 'base64url'),
      );
    expect(verified).toBe(true);
  });

  it('reuses a cached token instead of minting on every check', async () => {
    fetchSpy.mockResolvedValue(mockTokenResponse('ghs_cached', 3_600_000));

    await service.getInstallationToken(request);
    const second = await service.getInstallationToken(request);

    expect(second).toBe('ghs_cached');
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('re-mints rather than returning a token inside the expiry leeway', async () => {
    // 60s of life left, which is under the 300s refresh leeway: a long check run
    // could otherwise straddle the boundary and 401 mid-flight.
    fetchSpy.mockResolvedValueOnce(mockTokenResponse('ghs_stale', 60_000));
    fetchSpy.mockResolvedValueOnce(mockTokenResponse('ghs_fresh', 3_600_000));

    await service.getInstallationToken(request);
    const second = await service.getInstallationToken(request);

    expect(second).toBe('ghs_fresh');
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it('forceRefresh bypasses a still-valid cached token', async () => {
    fetchSpy.mockResolvedValueOnce(mockTokenResponse('ghs_first', 3_600_000));
    fetchSpy.mockResolvedValueOnce(mockTokenResponse('ghs_second', 3_600_000));

    await service.getInstallationToken(request);
    const refreshed = await service.getInstallationToken({
      ...request,
      forceRefresh: true,
    });

    expect(refreshed).toBe('ghs_second');
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it('invalidate() drops the cache so a reinstall does not reuse a dead token', async () => {
    fetchSpy.mockResolvedValueOnce(mockTokenResponse('ghs_old', 3_600_000));
    fetchSpy.mockResolvedValueOnce(mockTokenResponse('ghs_new', 3_600_000));

    await service.getInstallationToken(request);
    service.invalidate(CONNECTION);
    const after = await service.getInstallationToken(request);

    expect(after).toBe('ghs_new');
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });

  it('returns null when GitHub rejects the token request', async () => {
    fetchSpy.mockResolvedValue({
      ok: false,
      status: 404,
      json: async () => ({}),
      text: async () => 'Not Found',
    } as unknown as Response);

    await expect(service.getInstallationToken(request)).resolves.toBeNull();
  });

  it('returns null when no GitHub App credentials are configured', async () => {
    oauthAppRepository.findActiveByProviderAndOrg.mockResolvedValue(null);
    platformCredentialRepository.findActiveByProviderSlug.mockResolvedValue(null);

    await expect(service.getInstallationToken(request)).resolves.toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it('falls back to platform credentials when the org has none', async () => {
    oauthAppRepository.findActiveByProviderAndOrg.mockResolvedValue(null);
    platformCredentialRepository.findActiveByProviderSlug.mockResolvedValue(orgAppRow);
    fetchSpy.mockResolvedValue(mockTokenResponse('ghs_platform', 3_600_000));

    await expect(service.getInstallationToken(request)).resolves.toBe(
      'ghs_platform',
    );
  });

  it('normalises escaped newlines in a pasted private key', async () => {
    // Keys pasted through env vars arrive as a single line with literal \n,
    // which the signer would otherwise reject as malformed PEM.
    oauthAppRepository.findActiveByProviderAndOrg.mockResolvedValue({
      ...orgAppRow,
      encryptedClientSecret: encrypted(PRIVATE_KEY_PEM.replace(/\n/g, '\\n')),
    });
    fetchSpy.mockResolvedValue(mockTokenResponse('ghs_escaped', 3_600_000));

    await expect(service.getInstallationToken(request)).resolves.toBe(
      'ghs_escaped',
    );
  });

  describe('getInstallUrl', () => {
    it('builds the install URL from the app slug and carries the state', async () => {
      const url = await service.getInstallUrl(PROVIDER, ORG, 'state-123');

      expect(url).toBe(
        `https://github.com/apps/${APP_SLUG}/installations/new?state=state-123`,
      );
    });

    it('returns null when the app slug is not configured', async () => {
      oauthAppRepository.findActiveByProviderAndOrg.mockResolvedValue({
        ...orgAppRow,
        customSettings: {},
      });

      await expect(
        service.getInstallUrl(PROVIDER, ORG, 'state-123'),
      ).resolves.toBeNull();
    });
  });

  it('ignores providers that are not GitHub App integrations', async () => {
    await expect(
      service.getInstallationToken({ ...request, providerSlug: 'github' }),
    ).resolves.toBeNull();
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});

// Guard against the PEM fixture silently degrading into something unusable.
describe('test fixture', () => {
  it('produces a usable RSA private key', () => {
    expect(() => createPrivateKey(PRIVATE_KEY_PEM)).not.toThrow();
  });
});

describe('normalizePrivateKey', () => {
  const oneLine = PRIVATE_KEY_PEM.trim().replace(/\n/g, '');

  it('accepts a well-formed PEM unchanged', () => {
    expect(createPrivateKey(normalizePrivateKey(PRIVATE_KEY_PEM))).toBeDefined();
  });

  it('repairs literal \\n escapes', () => {
    const escaped = PRIVATE_KEY_PEM.replace(/\n/g, '\\n');
    expect(createPrivateKey(normalizePrivateKey(escaped))).toBeDefined();
  });

  it('repairs CRLF line endings', () => {
    const crlf = PRIVATE_KEY_PEM.replace(/\n/g, '\r\n');
    expect(createPrivateKey(normalizePrivateKey(crlf))).toBeDefined();
  });

  it('rebuilds a PEM whose newlines were stripped entirely', () => {
    // A single-line paste is what a plain <input> produces, and OpenSSL
    // rejects it with an opaque "DECODER routines::unsupported".
    expect(() => createPrivateKey(oneLine)).toThrow();
    expect(createPrivateKey(normalizePrivateKey(oneLine))).toBeDefined();
  });
});
