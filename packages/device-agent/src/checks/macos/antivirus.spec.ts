import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * Regression cover for the macOS antivirus check.
 *
 * The original implementation substring-matched vendor names against `ps aux`
 * output. Short names collide with unrelated command-line text — "ESET" matches
 * "PRESETS" and "--pseudonymization-set..." on a stock Mac — so the check
 * reported a product that was not installed, and reported it in preference to
 * the one that was, because it returned the first list match.
 *
 * That is a correctness bug with compliance consequences: the result is stored
 * as device evidence, so it misstated the security posture of every endpoint.
 * These tests pin the behaviour to install-path detection.
 */
vi.mock('node:fs', () => ({ existsSync: vi.fn() }));

const { existsSync } = await import('node:fs');
const { MacOSAntivirusCheck } = await import('./antivirus');

const XPROTECT = '/Library/Apple/System/Library/CoreServices/XProtect.bundle';
const mockPaths = (present: string[]) => {
  vi.mocked(existsSync).mockImplementation((p) => present.includes(String(p)));
};

describe('MacOSAntivirusCheck', () => {
  beforeEach(() => vi.mocked(existsSync).mockReset());
  afterEach(() => vi.restoreAllMocks());

  it('reports the vendor that is actually installed', async () => {
    mockPaths([XPROTECT, '/Library/Bitdefender']);
    const result = await new MacOSAntivirusCheck().run();

    expect(result.passed).toBe(true);
    expect(result.details.message).toContain('Bitdefender');
    expect(JSON.parse(result.details.raw).thirdPartyAV).toBe('Bitdefender');
  });

  it('does not report a vendor whose files are absent', async () => {
    // The original bug: ESET reported on a machine that only had Bitdefender.
    mockPaths([XPROTECT, '/Library/Bitdefender']);
    const result = await new MacOSAntivirusCheck().run();

    expect(result.details.message).not.toContain('ESET');
    expect(JSON.parse(result.details.raw).thirdPartyAV).not.toContain('ESET');
  });

  it('reports every vendor present, not just the first match', async () => {
    // A machine mid-migration between products must not look like it runs one.
    mockPaths([XPROTECT, '/Library/Bitdefender', '/Applications/Falcon.app']);
    const raw = JSON.parse((await new MacOSAntivirusCheck().run()).details.raw);

    expect(raw.thirdPartyAV).toContain('Bitdefender');
    expect(raw.thirdPartyAV).toContain('CrowdStrike');
  });

  it('reports no third-party AV when none is installed', async () => {
    mockPaths([XPROTECT]);
    const result = await new MacOSAntivirusCheck().run();

    expect(result.passed).toBe(true); // XProtect alone still passes
    expect(result.details.message).not.toContain('Third-party AV detected');
    expect(JSON.parse(result.details.raw).thirdPartyAV).toBeNull();
  });

  it('fails the check when XProtect is missing', async () => {
    mockPaths([]);
    const result = await new MacOSAntivirusCheck().run();

    expect(result.passed).toBe(false);
    expect(result.details.message).toContain('XProtect not found');
  });
});
