import { execSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import type { CheckResult } from '../../shared/types';
import type { ComplianceCheck } from '../types';

/**
 * Checks if antivirus or security software is active on Linux.
 *
 * Detection methods:
 *  1. Known AV products, matched against process names and install paths
 *  2. Check AppArmor enforcement status
 *  3. Check SELinux enforcement status
 *
 * Passes if any AV is detected OR a mandatory access control
 * framework (AppArmor/SELinux) is in enforcing mode.
 */
export class LinuxAntivirusCheck implements ComplianceCheck {
  checkType = 'antivirus' as const;
  displayName = 'Antivirus / Security Software';

  /**
   * Vendors are matched against exact process names and install paths, never
   * against raw `ps aux` text.
   *
   * Substring-matching full `ps aux` output produces false positives, because
   * that output carries every process's arguments: an unrelated `grep clamd`,
   * an editor holding `sophos-notes.txt`, or a tail of `/var/log/clamav` all
   * register as an installed product. Here that error also flips the verdict —
   * a detected AV is one of the things that makes this check pass, so a phantom
   * match reports an unprotected host as protected.
   *
   * Process names come from `ps -eo comm=`, which the kernel truncates to 15
   * characters; keep entries at or under that length.
   */
  private static readonly KNOWN_AV_VENDORS: ReadonlyArray<{
    name: string;
    processes: readonly string[];
    paths: readonly string[];
  }> = [
    {
      name: 'ClamAV',
      processes: ['clamd', 'freshclam'],
      paths: ['/etc/clamav', '/usr/sbin/clamd'],
    },
    {
      name: 'CrowdStrike',
      processes: ['falcon-sensor', 'falcond'],
      paths: ['/opt/CrowdStrike'],
    },
    {
      name: 'SentinelOne',
      processes: ['sentinelone', 'SentinelAgent'],
      paths: ['/opt/sentinelone'],
    },
    {
      name: 'Sophos',
      processes: ['savd', 'SophosMcsAgent'],
      paths: ['/opt/sophos-spl'],
    },
    {
      name: 'ESET',
      processes: ['esets_daemon'],
      paths: ['/opt/eset'],
    },
    {
      name: 'Bitdefender',
      processes: ['bdagent', 'bdsecd'],
      paths: ['/opt/bitdefender-security-tools'],
    },
    {
      name: 'McAfee',
      processes: ['McAfeeAgent', 'macompatsvc'],
      paths: ['/opt/McAfee', '/opt/isec'],
    },
    {
      name: 'Microsoft Defender',
      processes: ['mdatp', 'wdavdaemon'],
      paths: ['/opt/microsoft/mdatp'],
    },
  ];

  async run(): Promise<CheckResult> {
    try {
      const detectedAV = this.findAntivirus();
      const appArmorEnforcing = this.checkAppArmor();
      const seLinuxEnforcing = this.checkSELinux();

      const passed = detectedAV.length > 0 || appArmorEnforcing || seLinuxEnforcing;
      const details: string[] = [];

      if (detectedAV.length > 0) {
        details.push(`Antivirus detected: ${detectedAV.join(', ')}`);
      }

      if (appArmorEnforcing) {
        details.push('AppArmor is in enforcing mode');
      }

      if (seLinuxEnforcing) {
        details.push('SELinux is in enforcing mode');
      }

      if (!passed) {
        details.push('No antivirus software or mandatory access control detected');
      }

      return {
        checkType: this.checkType,
        passed,
        details: {
          method: 'process-name + install-path scan + apparmor + selinux',
          raw: JSON.stringify({
            detectedAV: detectedAV.length > 0 ? detectedAV.join(', ') : null,
            appArmorEnforcing,
            seLinuxEnforcing,
          }),
          message: details.join('. '),
        },
        checkedAt: new Date().toISOString(),
      };
    } catch (error) {
      return {
        checkType: this.checkType,
        passed: false,
        details: {
          method: 'process-name + install-path scan',
          raw: error instanceof Error ? error.message : String(error),
          message: 'Unable to determine antivirus status',
        },
        checkedAt: new Date().toISOString(),
      };
    }
  }

  /**
   * Reports every vendor found rather than only the first, so a host mid-
   * migration between products is not silently reported as running just one.
   */
  private findAntivirus(): string[] {
    const running = this.runningProcessNames();

    return LinuxAntivirusCheck.KNOWN_AV_VENDORS.filter(
      (vendor) =>
        vendor.processes.some((name) => running.has(name.toLowerCase())) ||
        vendor.paths.some((p) => existsSync(p)),
    ).map((vendor) => vendor.name);
  }

  private runningProcessNames(): ReadonlySet<string> {
    try {
      const output = execSync('ps -eo comm=', { encoding: 'utf-8', timeout: 10000 });
      return new Set(
        output
          .split('\n')
          .map((line) => line.trim().toLowerCase())
          .filter(Boolean),
      );
    } catch {
      // ps failure is non-critical; install-path detection still applies
      return new Set();
    }
  }

  private checkAppArmor(): boolean {
    try {
      const output = execSync('aa-status --enabled 2>/dev/null && echo "enabled"', {
        encoding: 'utf-8',
        timeout: 5000,
      });
      return output.trim().includes('enabled');
    } catch {
      // aa-status not available or not enforcing
    }

    try {
      const output = execSync('cat /sys/module/apparmor/parameters/enabled 2>/dev/null', {
        encoding: 'utf-8',
        timeout: 5000,
      });
      return output.trim() === 'Y';
    } catch {
      return false;
    }
  }

  private checkSELinux(): boolean {
    try {
      const output = execSync('getenforce 2>/dev/null', {
        encoding: 'utf-8',
        timeout: 5000,
      });
      return output.trim().toLowerCase() === 'enforcing';
    } catch {
      return false;
    }
  }
}
