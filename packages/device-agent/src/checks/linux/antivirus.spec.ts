import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * Regression cover for the Linux antivirus check.
 *
 * The original implementation substring-matched vendor names against `ps aux`
 * output, which includes every process's full argument list. Unrelated text
 * therefore registered as an installed product, and only the first list match
 * was ever reported.
 *
 * On Linux that bug is worse than its macOS counterpart: a detected AV is one
 * of the conditions that makes this check pass, so a phantom match reports an
 * unprotected host as protected — and the result is stored as device evidence.
 * These tests pin detection to exact process names and install paths.
 */
vi.mock('node:child_process', () => ({ execSync: vi.fn() }));
vi.mock('node:fs', () => ({ existsSync: vi.fn() }));

const { execSync } = await import('node:child_process');
const { existsSync } = await import('node:fs');
const { LinuxAntivirusCheck } = await import('./antivirus');

/** `ps -eo comm=` output: one bare process name per line, no arguments. */
const mockProcesses = (names: string[]) => {
  vi.mocked(execSync).mockImplementation((command) => {
    if (String(command).startsWith('ps ')) return `${names.join('\n')}\n`;
    throw new Error('not available');
  });
};

const mockPaths = (present: string[]) => {
  vi.mocked(existsSync).mockImplementation((p) => present.includes(String(p)));
};

const rawOf = (result: { details: { raw: string } }) => JSON.parse(result.details.raw);

describe('LinuxAntivirusCheck', () => {
  beforeEach(() => {
    mockProcesses([]);
    mockPaths([]);
  });

  afterEach(() => {
    vi.resetAllMocks();
  });

  it('detects a vendor by exact process name', async () => {
    mockProcesses(['systemd', 'clamd', 'sshd']);

    const result = await new LinuxAntivirusCheck().run();

    expect(rawOf(result).detectedAV).toBe('ClamAV');
    expect(result.passed).toBe(true);
  });

  it('detects a vendor by install path when no process is running', async () => {
    mockPaths(['/opt/CrowdStrike']);

    const result = await new LinuxAntivirusCheck().run();

    expect(rawOf(result).detectedAV).toBe('CrowdStrike');
    expect(result.passed).toBe(true);
  });

  it('does not match vendor names appearing in command arguments', async () => {
    // The bug: `ps aux` would render these as lines containing "clamd" and
    // "sophos", so substring matching claimed both products were installed.
    mockProcesses(['grep', 'tail', 'vim']);

    const result = await new LinuxAntivirusCheck().run();

    expect(rawOf(result).detectedAV).toBeNull();
  });

  it('does not report an unprotected host as protected', async () => {
    mockProcesses(['grep', 'tail']);
    mockPaths([]);

    const result = await new LinuxAntivirusCheck().run();

    expect(result.passed).toBe(false);
    expect(result.details.message).toContain('No antivirus software');
  });

  it('reports every vendor found, not just the first', async () => {
    mockProcesses(['clamd']);
    mockPaths(['/opt/sentinelone']);

    const result = await new LinuxAntivirusCheck().run();

    expect(rawOf(result).detectedAV).toContain('ClamAV');
    expect(rawOf(result).detectedAV).toContain('SentinelOne');
  });

  it('still passes on a host with no AV but enforcing SELinux', async () => {
    vi.mocked(execSync).mockImplementation((command) => {
      const cmd = String(command);
      if (cmd.startsWith('ps ')) return 'systemd\nsshd\n';
      if (cmd.startsWith('getenforce')) return 'Enforcing\n';
      throw new Error('not available');
    });

    const result = await new LinuxAntivirusCheck().run();

    expect(result.passed).toBe(true);
    expect(rawOf(result).seLinuxEnforcing).toBe(true);
    expect(rawOf(result).detectedAV).toBeNull();
  });

  it('falls back to install-path detection when ps fails', async () => {
    vi.mocked(execSync).mockImplementation(() => {
      throw new Error('ps unavailable');
    });
    mockPaths(['/opt/microsoft/mdatp']);

    const result = await new LinuxAntivirusCheck().run();

    expect(rawOf(result).detectedAV).toBe('Microsoft Defender');
    expect(result.passed).toBe(true);
  });
});
