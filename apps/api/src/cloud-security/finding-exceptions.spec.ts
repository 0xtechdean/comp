jest.mock('@db', () => ({
  db: { findingException: { findMany: jest.fn() } },
}));

import { db } from '@db';
import {
  ActiveExceptionSet,
  loadActiveExceptionSet,
  prefixRuleMatches,
} from './finding-exceptions';

const findMany = jest.mocked(db.findingException.findMany);

describe('ActiveExceptionSet', () => {
  it('matches by (connectionId, checkId, resourceId)', () => {
    const set = new ActiveExceptionSet([
      ActiveExceptionSet.key('c1', 'aws-s3-public-access', 'bucket-1'),
    ]);
    expect(set.has('c1', 'aws-s3-public-access', 'bucket-1')).toBe(true);
    expect(set.has('c1', 'aws-s3-public-access', 'bucket-2')).toBe(false);
    expect(set.has('c2', 'aws-s3-public-access', 'bucket-1')).toBe(false);
    expect(set.size).toBe(1);
  });

  it('exposes excepted resourceIds grouped by (connectionId, checkId)', () => {
    const set = new ActiveExceptionSet([
      ActiveExceptionSet.key('c1', 'check-a', 'r1'),
      ActiveExceptionSet.key('c1', 'check-a', 'r2'),
      ActiveExceptionSet.key('c1', 'check-b', 'r3'),
    ]);
    expect(new Set(set.exceptedResourceIds('c1', 'check-a'))).toEqual(
      new Set(['r1', 'r2']),
    );
    expect(set.exceptedResourceIds('c1', 'check-b')).toEqual(['r3']);
    // Nothing excepted for this pair → empty (callers skip the count query).
    expect(set.exceptedResourceIds('c1', 'check-c')).toEqual([]);
    expect(set.exceptedResourceIds('c2', 'check-a')).toEqual([]);
  });

  it('reconstructs resourceIds that themselves contain the "::" delimiter', () => {
    const resourceId = 'arn:aws:s3:::my::weird::bucket';
    const set = new ActiveExceptionSet([
      ActiveExceptionSet.key('c1', 'check-a', resourceId),
    ]);
    expect(set.has('c1', 'check-a', resourceId)).toBe(true);
    expect(set.exceptedResourceIds('c1', 'check-a')).toEqual([resourceId]);
  });

  it('exposes exception metadata via infoFor when built with it', () => {
    const key = ActiveExceptionSet.key('c1', 'check-a', 'r1');
    const set = new ActiveExceptionSet(
      [key],
      new Map([[key, { id: 'fex_1', reason: 'Intentional public bucket' }]]),
    );
    expect(set.infoFor('c1', 'check-a', 'r1')).toEqual({
      id: 'fex_1',
      reason: 'Intentional public bucket',
    });
    expect(set.infoFor('c1', 'check-a', 'r2')).toBeNull();
  });

  it('infoFor returns null on a set built from bare keys (has() still true)', () => {
    const set = new ActiveExceptionSet([
      ActiveExceptionSet.key('c1', 'check-a', 'r1'),
    ]);
    expect(set.has('c1', 'check-a', 'r1')).toBe(true);
    expect(set.infoFor('c1', 'check-a', 'r1')).toBeNull();
  });
});

describe('ActiveExceptionSet — prefix (class) rules', () => {
  const secretArn = (stack: string) =>
    `arn:aws:secretsmanager:eu-central-1:111:secret:cloud/stacks/${stack}-AbCdEf`;
  const rule = {
    connectionId: 'c1',
    checkIdPrefix: 'secrets-no-rotation-cloud/stacks/dep_',
    resourceIdPrefix:
      'arn:aws:secretsmanager:eu-central-1:111:secret:cloud/stacks/dep_',
    info: { id: 'fex_class', reason: 'One secret per stack, written once.' },
  };
  const set = new ActiveExceptionSet([], new Map(), [rule]);

  it('covers every finding whose check id and resource id both start with the prefixes', () => {
    expect(
      set.has(
        'c1',
        'secrets-no-rotation-cloud/stacks/dep_aaa',
        secretArn('dep_aaa'),
      ),
    ).toBe(true);
    expect(
      set.has(
        'c1',
        'secrets-no-rotation-cloud/stacks/dep_new',
        secretArn('dep_new'),
      ),
    ).toBe(true);
    expect(set.size).toBe(1);
  });

  it('needs BOTH prefixes to match, on the same connection', () => {
    // Resource matches, check does not.
    expect(set.has('c1', 'secrets-unused-30d', secretArn('dep_aaa'))).toBe(
      false,
    );
    // Check matches, resource does not.
    expect(
      set.has(
        'c1',
        'secrets-no-rotation-cloud/stacks/dep_aaa',
        'arn:aws:secretsmanager:eu-central-1:111:secret:prod/app-XyZ',
      ),
    ).toBe(false);
    // Other connection.
    expect(
      set.has(
        'c2',
        'secrets-no-rotation-cloud/stacks/dep_aaa',
        secretArn('dep_aaa'),
      ),
    ).toBe(false);
  });

  it('returns the class exception metadata from infoFor', () => {
    expect(
      set.infoFor(
        'c1',
        'secrets-no-rotation-cloud/stacks/dep_b',
        secretArn('dep_b'),
      ),
    ).toEqual({
      id: 'fex_class',
      reason: 'One secret per stack, written once.',
    });
  });

  it('prefers the exact exception metadata when both cover a finding', () => {
    const checkId = 'secrets-no-rotation-cloud/stacks/dep_x';
    const key = ActiveExceptionSet.key('c1', checkId, secretArn('dep_x'));
    const both = new ActiveExceptionSet(
      [key],
      new Map([[key, { id: 'fex_exact', reason: 'Exact exception reason.' }]]),
      [rule],
    );
    expect(both.infoFor('c1', checkId, secretArn('dep_x'))?.id).toBe(
      'fex_exact',
    );
  });

  it('exposes the resource-id prefixes that apply to a (connection, check) pair', () => {
    expect(
      set.exceptedResourceIdPrefixes(
        'c1',
        'secrets-no-rotation-cloud/stacks/dep_aaa',
      ),
    ).toEqual([rule.resourceIdPrefix]);
    expect(set.exceptedResourceIdPrefixes('c1', 'iam-no-mfa')).toEqual([]);
    expect(
      set.exceptedResourceIdPrefixes(
        'c2',
        'secrets-no-rotation-cloud/stacks/dep_aaa',
      ),
    ).toEqual([]);
    // Prefix rules never leak into the exact resource-id list.
    expect(
      set.exceptedResourceIds('c1', 'secrets-no-rotation-cloud/stacks/dep_aaa'),
    ).toEqual([]);
  });
});

describe('prefixRuleMatches', () => {
  const rule = {
    connectionId: 'c1',
    checkIdPrefix: 'check-',
    resourceIdPrefix: 'res-',
  };

  it('matches only when connection, check prefix and resource prefix all match', () => {
    expect(
      prefixRuleMatches({
        rule,
        connectionId: 'c1',
        checkId: 'check-1',
        resourceId: 'res-1',
      }),
    ).toBe(true);
    expect(
      prefixRuleMatches({
        rule,
        connectionId: 'c2',
        checkId: 'check-1',
        resourceId: 'res-1',
      }),
    ).toBe(false);
    expect(
      prefixRuleMatches({
        rule,
        connectionId: 'c1',
        checkId: 'other',
        resourceId: 'res-1',
      }),
    ).toBe(false);
    expect(
      prefixRuleMatches({
        rule,
        connectionId: 'c1',
        checkId: 'check-1',
        resourceId: 'other',
      }),
    ).toBe(false);
  });
});

describe('loadActiveExceptionSet', () => {
  beforeEach(() => jest.clearAllMocks());

  it('builds the set from active exceptions, carrying id + reason', async () => {
    findMany.mockResolvedValue([
      {
        id: 'fex_1',
        connectionId: 'c1',
        checkId: 'aws-s3-public-access',
        resourceId: 'bucket-1',
        reason: 'Bucket only hosts a static website redirect.',
      },
    ] as never);

    const set = await loadActiveExceptionSet('org_1');

    expect(set.has('c1', 'aws-s3-public-access', 'bucket-1')).toBe(true);
    expect(set.infoFor('c1', 'aws-s3-public-access', 'bucket-1')).toEqual({
      id: 'fex_1',
      reason: 'Bucket only hosts a static website redirect.',
    });
    // Query only active exceptions (not revoked, not expired).
    expect(findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        where: expect.objectContaining({
          organizationId: 'org_1',
          revokedAt: null,
        }),
      }),
    );
  });

  it('loads prefix rows as class rules, not exact keys', async () => {
    findMany.mockResolvedValue([
      {
        id: 'fex_exact',
        connectionId: 'c1',
        checkId: 'aws-s3-public-access',
        resourceId: 'bucket-1',
        reason: 'Bucket only hosts a static website redirect.',
        match: 'exact',
      },
      {
        id: 'fex_class',
        connectionId: 'c1',
        checkId: 'secrets-no-rotation-cloud/stacks/dep_',
        resourceId:
          'arn:aws:secretsmanager:eu-central-1:111:secret:cloud/stacks/dep_',
        reason: 'One secret bundle per stack, written once.',
        match: 'prefix',
      },
    ] as never);

    const set = await loadActiveExceptionSet('org_1');

    expect(set.size).toBe(2);
    expect(set.has('c1', 'aws-s3-public-access', 'bucket-1')).toBe(true);
    expect(
      set.has(
        'c1',
        'secrets-no-rotation-cloud/stacks/dep_123',
        'arn:aws:secretsmanager:eu-central-1:111:secret:cloud/stacks/dep_123-Qq1',
      ),
    ).toBe(true);
    // The prefix row's own strings are not an exact key.
    expect(
      set.exceptedResourceIds('c1', 'secrets-no-rotation-cloud/stacks/dep_'),
    ).toEqual([]);
    expect(findMany).toHaveBeenCalledWith(
      expect.objectContaining({
        select: expect.objectContaining({ match: true }),
      }),
    );
  });

  it('fail-safe: returns an empty set if the lookup throws (suppress nothing)', async () => {
    findMany.mockRejectedValue(new Error('db down'));
    const set = await loadActiveExceptionSet('org_1');
    expect(set.size).toBe(0);
    expect(set.has('c1', 'aws-s3-public-access', 'bucket-1')).toBe(false);
  });
});
