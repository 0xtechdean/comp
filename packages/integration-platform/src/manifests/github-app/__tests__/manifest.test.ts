import { describe, expect, it } from 'bun:test';
import { getAllManifests, getManifest } from '../../../registry';
import { manifest as githubManifest } from '../../github';
import { githubAppManifest } from '../index';

/**
 * The `github-app` integration must request read-only, fine-grained access via a
 * GitHub App *installation* — access owned by the organization, not by whoever
 * clicked Authorize — while leaving the legacy `github` OAuth integration
 * completely untouched so existing connections keep working.
 */
describe('github-app manifest', () => {
  it('is registered in the registry', () => {
    expect(getManifest('github-app')).toBeDefined();
    expect(getAllManifests().some((m) => m.id === 'github-app')).toBe(true);
  });

  it('authenticates as an installation, not as a user', () => {
    const { auth } = githubAppManifest;
    expect(auth.type).toBe('github_app');
    if (auth.type !== 'github_app') return;
    expect(auth.config.installationTokenUrl).toContain(
      '/app/installations/{INSTALLATION_ID}/access_tokens',
    );
    // An App JWT is capped at 10 minutes by GitHub; staying under it avoids
    // clock-skew rejections.
    expect(auth.config.appJwtExpirySeconds).toBeLessThan(600);
  });

  it('requests every permission as read-only', () => {
    const { auth } = githubAppManifest;
    if (auth.type !== 'github_app') throw new Error('expected github_app auth');
    const granted = [
      ...Object.values(auth.config.repositoryPermissions ?? {}),
      ...Object.values(auth.config.organizationPermissions ?? {}),
    ];
    expect(granted.length).toBeGreaterThan(0);
    expect(granted.every((level) => level === 'read')).toBe(true);
  });

  it('reuses the exact same checks as the legacy github manifest', () => {
    const appCheckIds = githubAppManifest.checks?.map((c) => c.id).sort();
    const legacyCheckIds = githubManifest.checks?.map((c) => c.id).sort();
    expect(appCheckIds).toEqual(legacyCheckIds);
    expect(appCheckIds?.length).toBe(5);
  });

  it('leaves the legacy github manifest untouched (still OAuth `repo` scope)', () => {
    expect(githubManifest.id).toBe('github');
    expect(githubManifest.name).toBe('GitHub');
    if (githubManifest.auth.type !== 'oauth2') {
      throw new Error('expected oauth2 auth');
    }
    expect(githubManifest.auth.config.scopes).toContain('repo');
  });
});
