import { describe, expect, it } from 'bun:test';
import { accountTwoFactorCheck } from '../checks/account-2fa';
import { workspaceTwoFactorCheck } from '../checks/workspace-2fa';
import { projectVisibilityCheck } from '../checks/project-visibility';
import { projectInventoryCheck } from '../checks/project-inventory';
import type { CheckContext, CheckFindingResult, CheckPassingResult } from '../../../types';

interface RunResult {
  passes: CheckPassingResult[];
  fails: CheckFindingResult[];
}

/**
 * Build a CheckContext whose `graphql` returns a fixed payload (the Railway
 * checks each issue exactly one query), capturing pass/fail emissions.
 */
async function run(
  check: { run: (ctx: CheckContext) => Promise<void> },
  data: unknown,
): Promise<RunResult> {
  const passes: CheckPassingResult[] = [];
  const fails: CheckFindingResult[] = [];
  const ctx = {
    accessToken: '',
    credentials: { api_key: 'tok' },
    variables: {},
    connectionId: 'conn_1',
    organizationId: 'org_1',
    log: () => {},
    warn: () => {},
    error: () => {},
    pass: (r: CheckPassingResult) => passes.push(r),
    fail: (f: CheckFindingResult) => fails.push(f),
    graphql: (async () => data) as CheckContext['graphql'],
  } as unknown as CheckContext;

  await check.run(ctx);
  return { passes, fails };
}

describe('railway account-2fa check', () => {
  it('fails high when the account has no 2FA or passkey', async () => {
    const { passes, fails } = await run(accountTwoFactorCheck, {
      me: { id: 'u1', email: 'a@b.co', name: 'A', has2FA: false, hasPasskeys: false },
    });
    expect(passes).toHaveLength(0);
    expect(fails).toHaveLength(1);
    expect(fails[0].severity).toBe('high');
    expect(fails[0].resourceId).toBe('u1');
  });

  it('passes when 2FA is enabled', async () => {
    const { passes, fails } = await run(accountTwoFactorCheck, {
      me: { id: 'u1', email: 'a@b.co', name: 'A', has2FA: true, hasPasskeys: false },
    });
    expect(fails).toHaveLength(0);
    expect(passes).toHaveLength(1);
  });

  it('passes when only a passkey is enrolled', async () => {
    const { fails } = await run(accountTwoFactorCheck, {
      me: { id: 'u1', email: 'a@b.co', name: 'A', has2FA: false, hasPasskeys: true },
    });
    expect(fails).toHaveLength(0);
  });
});

describe('railway workspace-2fa check', () => {
  it('fails enforcement + one finding per member without 2FA', async () => {
    const { passes, fails } = await run(workspaceTwoFactorCheck, {
      me: {
        workspaces: [
          {
            id: 'ws1',
            name: 'Team',
            has2FAEnforcement: false,
            hasSAML: false,
            projectCount: 2,
            usersWithout2FA: ['a@b.co', 'c@d.co'],
          },
        ],
      },
    });
    // 1 enforcement finding + 2 member findings
    expect(fails).toHaveLength(3);
    expect(fails.every((f) => f.severity === 'high')).toBe(true);
    expect(fails.filter((f) => f.resourceType === 'railway-workspace-member')).toHaveLength(2);
    expect(passes).toHaveLength(0);
  });

  it('passes an enforced workspace with all members enrolled', async () => {
    const { passes, fails } = await run(workspaceTwoFactorCheck, {
      me: {
        workspaces: [
          {
            id: 'ws1',
            name: 'Team',
            has2FAEnforcement: true,
            hasSAML: true,
            projectCount: 0,
            usersWithout2FA: [],
          },
        ],
      },
    });
    expect(fails).toHaveLength(0);
    expect(passes).toHaveLength(1);
  });
});

describe('railway project-visibility check', () => {
  const workspaces = [
    {
      id: 'ws1',
      name: 'Team',
      projects: {
        edges: [
          { node: { id: 'p1', name: 'public-one', isPublic: true } },
          { node: { id: 'p2', name: 'private-one', isPublic: false } },
        ],
      },
    },
  ];

  it('fails public projects and passes private ones', async () => {
    const { passes, fails } = await run(projectVisibilityCheck, { me: { workspaces } });
    expect(fails).toHaveLength(1);
    expect(fails[0].resourceId).toBe('p1');
    expect(fails[0].severity).toBe('high');
    expect(passes).toHaveLength(1);
    expect(passes[0].resourceId).toBe('p2');
  });
});

describe('railway project-inventory check', () => {
  it('emits a passing evidence result per project', async () => {
    const { passes, fails } = await run(projectInventoryCheck, {
      me: {
        workspaces: [
          {
            id: 'ws1',
            name: 'Team',
            projects: {
              edges: [
                {
                  node: {
                    id: 'p1',
                    name: 'svc',
                    isPublic: false,
                    environments: { edges: [{ node: { id: 'e1', name: 'production' } }] },
                    services: { edges: [{ node: { id: 's1', name: 'api' } }] },
                  },
                },
              ],
            },
          },
        ],
      },
    });
    expect(fails).toHaveLength(0);
    expect(passes).toHaveLength(1);
    expect(passes[0].evidence.environments).toEqual(['production']);
  });
});
