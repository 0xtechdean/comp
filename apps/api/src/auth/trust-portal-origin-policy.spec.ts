import {
  isTrustPortalPath,
  isTrustPortalRequestAllowed,
} from './trust-portal-origin-policy';

const SLUG = 'acme';

const allowed = (path: string, slug: string | null = SLUG) =>
  isTrustPortalRequestAllowed({ path, slug });

describe('isTrustPortalPath', () => {
  it('matches the trust-access surface and nothing else', () => {
    expect(isTrustPortalPath('/v1/trust-access')).toBe(true);
    expect(isTrustPortalPath('/v1/trust-access/acme/faqs')).toBe(true);
    expect(isTrustPortalPath('/v1/trust-portal/settings')).toBe(false);
    expect(isTrustPortalPath('/v1/organization')).toBe(false);
  });

  it('does not treat a lookalike prefix as the trust surface', () => {
    // Guards against a bare startsWith on the prefix, which would admit a
    // sibling route like /v1/trust-access-admin.
    expect(isTrustPortalPath('/v1/trust-access-admin/requests')).toBe(false);
  });
});

describe('isTrustPortalRequestAllowed', () => {
  describe('the portal keeps its own visitor routes', () => {
    it.each([
      '/v1/trust-access/acme/faqs',
      '/v1/trust-access/acme/overview',
      '/v1/trust-access/acme/requests',
      '/v1/trust-access/acme/reclaim',
      '/v1/trust-access/acme/security-questionnaire',
      '/v1/trust-access/acme/custom-links',
      '/v1/trust-access/acme/vendors',
    ])('allows %s', (path) => {
      expect(allowed(path)).toBe(true);
    });

    it('ignores a trailing slash', () => {
      expect(allowed('/v1/trust-access/acme/faqs/')).toBe(true);
    });
  });

  describe('token-keyed routes', () => {
    // The token is the authorization: unguessable, issued to one named visitor,
    // and carrying no slug to scope against.
    it.each([
      '/v1/trust-access/access/tok_123',
      '/v1/trust-access/access/tok_123/policies',
      '/v1/trust-access/access/tok_123/documents/doc_1',
      '/v1/trust-access/nda/tok_123',
      '/v1/trust-access/nda/tok_123/sign',
    ])('allows %s', (path) => {
      expect(allowed(path)).toBe(true);
    });

    it('allows them even when the portal has no slug of its own', () => {
      expect(allowed('/v1/trust-access/access/tok_123', null)).toBe(true);
    });
  });

  describe('cross-tenant isolation', () => {
    it("SECURITY: refuses another portal's slug", () => {
      // The whole point of the scoping: acme.com must not read rival's portal
      // just because both are published custom domains.
      expect(allowed('/v1/trust-access/rival/faqs')).toBe(false);
      expect(allowed('/v1/trust-access/rival/overview')).toBe(false);
    });

    it('SECURITY: a portal with no slug reaches no slug-keyed route', () => {
      expect(allowed('/v1/trust-access/acme/faqs', null)).toBe(false);
    });

    it('matches the slug exactly, not by prefix', () => {
      expect(allowed('/v1/trust-access/acme-evil/faqs')).toBe(false);
      expect(allowed('/v1/trust-access/ACME/faqs')).toBe(false);
    });
  });

  describe('everything else is refused', () => {
    it('SECURITY: refuses the admin half of the same controller', () => {
      expect(allowed('/v1/trust-access/admin/requests')).toBe(false);
      expect(allowed('/v1/trust-access/admin/grants/g_1/revoke')).toBe(false);
    });

    it('SECURITY: refuses admin even for a portal whose slug is "admin"', () => {
      // Slug matching must not become a way back into the admin routes.
      expect(allowed('/v1/trust-access/admin/requests', 'admin')).toBe(false);
    });

    it('SECURITY: refuses the rest of the API', () => {
      expect(allowed('/v1/organization')).toBe(false);
      expect(allowed('/v1/policies')).toBe(false);
      expect(allowed('/v1/trust-portal/settings')).toBe(false);
      expect(allowed('/api/auth/get-session')).toBe(false);
    });

    it('refuses the collection root, which addresses no portal', () => {
      expect(allowed('/v1/trust-access')).toBe(false);
    });
  });
});
