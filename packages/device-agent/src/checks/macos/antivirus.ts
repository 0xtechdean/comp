import { existsSync } from 'node:fs';
import type { CheckResult } from '../../shared/types';
import type { ComplianceCheck } from '../types';

/**
 * Checks if antivirus protection is active on macOS.
 *
 * On macOS, XProtect is built-in and always active on supported versions.
 * We verify:
 *  1. XProtect bundle exists at the expected path
 *  2. Optionally detect third-party AV software
 */
export class MacOSAntivirusCheck implements ComplianceCheck {
  checkType = 'antivirus' as const;
  displayName = 'Antivirus (XProtect)';

  private static readonly XPROTECT_PATHS = [
    '/Library/Apple/System/Library/CoreServices/XProtect.bundle',
    '/System/Library/CoreServices/XProtect.bundle',
  ];

  /**
   * Vendors are matched against install paths, not raw `ps aux` text.
   *
   * Substring-matching process output produces false positives: short vendor
   * names collide with unrelated command-line arguments (e.g. "ESET" matches
   * "PRE**SET**S" and "--pseudonymization-**set**..." on a stock Mac), which
   * silently misreports which product is installed. Paths are unambiguous.
   */
  private static readonly KNOWN_AV_VENDORS: ReadonlyArray<{
    name: string;
    paths: readonly string[];
  }> = [
    { name: 'Bitdefender', paths: ['/Library/Bitdefender', '/Applications/Bitdefender'] },
    { name: 'CrowdStrike', paths: ['/Applications/Falcon.app', '/Library/CS'] },
    { name: 'SentinelOne', paths: ['/Applications/SentinelOne', '/Library/Sentinel'] },
    { name: 'Sophos', paths: ['/Applications/Sophos', '/Library/Sophos Anti-Virus'] },
    { name: 'MalwareBytes', paths: ['/Applications/Malwarebytes.app'] },
    {
      name: 'ESET',
      paths: ['/Applications/ESET Endpoint Security.app', '/Library/Application Support/ESET'],
    },
    { name: 'Norton', paths: ['/Applications/Norton 360.app', '/Applications/Symantec Solutions'] },
    {
      name: 'McAfee',
      paths: ['/Applications/McAfee Endpoint Security for Mac.app', '/Library/McAfee'],
    },
    {
      name: 'Kaspersky',
      paths: ['/Applications/Kaspersky.app', '/Library/Application Support/Kaspersky Lab'],
    },
    { name: 'Avast', paths: ['/Applications/Avast.app'] },
    { name: 'AVG', paths: ['/Applications/AVG AntiVirus.app'] },
    { name: 'Trend Micro', paths: ['/Applications/Trend Micro Security.app'] },
    { name: 'Webroot', paths: ['/Applications/Webroot SecureAnywhere.app'] },
  ];

  async run(): Promise<CheckResult> {
    try {
      // Check XProtect
      const xprotectExists = MacOSAntivirusCheck.XPROTECT_PATHS.some((p) => existsSync(p));

      // Detect third-party AV by install path. Report every vendor found rather
      // than only the first, so a machine mid-migration between products is not
      // silently reported as running just one of them.
      const detectedAV = MacOSAntivirusCheck.KNOWN_AV_VENDORS.filter((vendor) =>
        vendor.paths.some((p) => existsSync(p)),
      ).map((vendor) => vendor.name);
      const thirdPartyAV = detectedAV.length > 0 ? detectedAV.join(', ') : null;

      const passed = xprotectExists;
      const details: string[] = [];

      if (xprotectExists) {
        details.push('XProtect is active');
      } else {
        details.push('XProtect not found');
      }

      if (thirdPartyAV) {
        details.push(`Third-party AV detected: ${thirdPartyAV}`);
      }

      return {
        checkType: this.checkType,
        passed,
        details: {
          method: 'xprotect-bundle-check + install-path-scan',
          raw: JSON.stringify({ xprotectExists, thirdPartyAV }),
          message: details.join('. '),
        },
        checkedAt: new Date().toISOString(),
      };
    } catch (error) {
      return {
        checkType: this.checkType,
        passed: false,
        details: {
          method: 'xprotect-bundle-check',
          raw: error instanceof Error ? error.message : String(error),
          message: 'Unable to determine antivirus status',
        },
        checkedAt: new Date().toISOString(),
      };
    }
  }
}
