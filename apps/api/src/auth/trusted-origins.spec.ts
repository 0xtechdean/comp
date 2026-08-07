const mockTrustFindMany = jest.fn();

jest.mock('@db', () => ({
  db: { trust: { findMany: mockTrustFindMany } },
}));

// No Upstash configured in tests, so the lookup goes straight to the DB and
// every call re-reads the mock — which is what these assertions rely on.
jest.mock('@upstash/redis', () => ({
  Redis: class {
    get = jest.fn();
    set = jest.fn();
  },
}));

import { isTrustedOrigin, isTrustedOriginForRequest } from './trusted-origins';

const PORTAL_ORIGIN = 'https://trust.acme.com';
const OTHER_PORTAL_ORIGIN = 'https://trust.rival.com';

const get = (params: { origin: string; path: string; method?: string }) =>
  isTrustedOriginForRequest({
    method: params.method ?? 'GET',
    origin: params.origin,
    path: params.path,
  });

beforeEach(() => {
  jest.clearAllMocks();
  jest.spyOn(console, 'warn').mockImplementation(() => undefined);
  mockTrustFindMany.mockResolvedValue([
    { domain: 'trust.acme.com', friendlyUrl: 'acme' },
    { domain: 'trust.rival.com', friendlyUrl: 'rival' },
  ]);
});

afterEach(() => {
  jest.restoreAllMocks();
});

describe('isTrustedOriginForRequest', () => {
  it('admits our own apps for anything', async () => {
    await expect(
      get({ origin: 'https://app.trycomp.ai', path: '/v1/organization' }),
    ).resolves.toBe(true);
  });

  it("admits a custom domain for its own portal's routes", async () => {
    await expect(
      get({ origin: PORTAL_ORIGIN, path: '/v1/trust-access/acme/faqs' }),
    ).resolves.toBe(true);
  });

  it('admits the token-keyed routes a portal visitor uses', async () => {
    await expect(
      get({ origin: PORTAL_ORIGIN, path: '/v1/trust-access/access/tok_1' }),
    ).resolves.toBe(true);
  });

  it("SECURITY: refuses a custom domain reaching another tenant's portal", async () => {
    await expect(
      get({ origin: PORTAL_ORIGIN, path: '/v1/trust-access/rival/faqs' }),
    ).resolves.toBe(false);
    await expect(
      get({ origin: OTHER_PORTAL_ORIGIN, path: '/v1/trust-access/acme/faqs' }),
    ).resolves.toBe(false);
  });

  it('SECURITY: refuses a custom domain reaching the rest of the API', async () => {
    // The point of the change: being a published portal no longer grants an
    // origin the whole surface.
    await expect(
      get({ origin: PORTAL_ORIGIN, path: '/v1/organization' }),
    ).resolves.toBe(false);
    await expect(
      get({ origin: PORTAL_ORIGIN, path: '/v1/trust-portal/settings' }),
    ).resolves.toBe(false);
  });

  it('SECURITY: refuses a custom domain on the admin routes, including writes', async () => {
    // Same check backs the CSRF guard, so this covers blind writes too.
    await expect(
      get({
        origin: PORTAL_ORIGIN,
        method: 'POST',
        path: '/v1/trust-access/admin/requests/req_1/approve',
      }),
    ).resolves.toBe(false);
  });

  it('SECURITY: refuses an origin that is not a published portal at all', async () => {
    await expect(
      get({ origin: 'https://evil.com', path: '/v1/trust-access/acme/faqs' }),
    ).resolves.toBe(false);
  });

  it('logs a denial so a route we failed to account for is diagnosable', async () => {
    await get({ origin: PORTAL_ORIGIN, path: '/v1/organization' });

    expect(console.warn).toHaveBeenCalledWith(
      expect.stringContaining('/v1/organization'),
    );
  });

  it('refuses a malformed origin rather than throwing', async () => {
    await expect(
      get({ origin: 'not a url', path: '/v1/trust-access/acme/faqs' }),
    ).resolves.toBe(false);
  });

  it('stays closed when the domain lookup fails', async () => {
    jest.spyOn(console, 'error').mockImplementation(() => undefined);
    mockTrustFindMany.mockRejectedValue(new Error('db down'));

    await expect(
      get({ origin: PORTAL_ORIGIN, path: '/v1/trust-access/acme/faqs' }),
    ).resolves.toBe(false);
  });
});

describe('isTrustedOrigin', () => {
  // Kept for callers that only ask "is this origin known at all"; the
  // request-scoped check above is what the middlewares use.
  it('still recognises a published custom domain', async () => {
    await expect(isTrustedOrigin(PORTAL_ORIGIN)).resolves.toBe(true);
    await expect(isTrustedOrigin('https://evil.com')).resolves.toBe(false);
  });
});
