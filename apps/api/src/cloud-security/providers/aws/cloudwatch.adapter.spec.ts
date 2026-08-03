const mockTrailSend = jest.fn();
const mockLogsSend = jest.fn();
const mockCwSend = jest.fn();

jest.mock('@aws-sdk/client-cloudtrail', () => ({
  CloudTrailClient: jest.fn(() => ({ send: mockTrailSend })),
  DescribeTrailsCommand: jest.fn((input: unknown) => ({
    _cmd: 'DescribeTrails',
    input,
  })),
}));
jest.mock('@aws-sdk/client-cloudwatch-logs', () => ({
  CloudWatchLogsClient: jest.fn(() => ({ send: mockLogsSend })),
  DescribeMetricFiltersCommand: jest.fn((input: unknown) => ({
    _cmd: 'DescribeMetricFilters',
    input,
  })),
}));
jest.mock('@aws-sdk/client-cloudwatch', () => ({
  CloudWatchClient: jest.fn(() => ({ send: mockCwSend })),
  DescribeAlarmsForMetricCommand: jest.fn((input: unknown) => ({
    _cmd: 'DescribeAlarmsForMetric',
    input,
  })),
}));

import { CloudWatchAdapter, logGroupNameFromArn, regionFromArn } from './cloudwatch.adapter';

const CREDS = {
  accessKeyId: 'AKIA',
  secretAccessKey: 'secret',
  sessionToken: 'token',
};

const scan = () =>
  new CloudWatchAdapter().scan({ credentials: CREDS, region: 'us-east-1' });

beforeEach(() => {
  jest.clearAllMocks();
  mockCwSend.mockResolvedValue({ MetricAlarms: [] });
});

describe('logGroupNameFromArn', () => {
  it('derives the bare name and strips the trailing :*', () => {
    expect(
      logGroupNameFromArn(
        'arn:aws:logs:us-east-1:123456789012:log-group:aws-cloudtrail-logs-xyz:*',
      ),
    ).toBe('aws-cloudtrail-logs-xyz');
  });

  it('handles an ARN without a trailing :*', () => {
    expect(
      logGroupNameFromArn('arn:aws:logs:us-east-1:123:log-group:my-lg'),
    ).toBe('my-lg');
  });

  it('handles the GovCloud partition', () => {
    expect(
      logGroupNameFromArn(
        'arn:aws-us-gov:logs:us-gov-west-1:123:log-group:ct-logs:*',
      ),
    ).toBe('ct-logs');
  });

  it('returns null for a missing or malformed ARN', () => {
    expect(logGroupNameFromArn(undefined)).toBeNull();
    expect(logGroupNameFromArn('not-an-arn')).toBeNull();
  });
});

describe('CloudWatchAdapter — CloudTrail log group resolution', () => {
  it('injects the real log group name into the metric-filter-missing finding (the customer bug)', async () => {
    mockTrailSend.mockResolvedValue({
      trailList: [
        {
          Name: 'main',
          CloudWatchLogsLogGroupArn:
            'arn:aws:logs:us-east-1:123456789012:log-group:my-ct-logs:*',
        },
      ],
    });
    mockLogsSend.mockResolvedValue({ metricFilters: [] }); // nothing configured

    const findings = await scan();
    const missing = findings.find((f) =>
      f.title.includes('metric filter missing'),
    );

    expect(missing).toBeDefined();
    expect(missing!.evidence?.cloudWatchLogGroupName).toBe('my-ct-logs');
    expect(missing!.remediation).toContain('logGroupName set to "my-ct-logs"');
    // The old generic phrasing that forced the AI to guess must be gone.
    expect(missing!.remediation).not.toContain(
      'logGroupName set to the CloudTrail log group',
    );
  });

  it('uses the existing filter\'s own log group for the no-transformation update', async () => {
    mockTrailSend.mockResolvedValue({
      trailList: [
        {
          Name: 'main',
          CloudWatchLogsLogGroupArn:
            'arn:aws:logs:us-east-1:123:log-group:my-ct-logs:*',
        },
      ],
    });
    // A filter matching CIS 4.3 (Root account usage) keywords, but with no
    // metric transformation → "no metric transformation" finding.
    mockLogsSend.mockResolvedValue({
      metricFilters: [
        {
          filterName: 'root-filter',
          filterPattern: '{ $.userIdentity.type = "Root" }',
          logGroupName: 'existing-lg',
          metricTransformations: [],
        },
      ],
    });

    const findings = await scan();
    const noTransform = findings.find((f) =>
      f.title.includes('no metric transformation'),
    );

    expect(noTransform).toBeDefined();
    expect(noTransform!.evidence?.logGroupName).toBe('existing-lg');
    expect(noTransform!.remediation).toContain('logGroupName set to "existing-lg"');
  });

  it('recognises the CIS-conformant 4.1 pattern instead of reporting it missing', async () => {
    mockTrailSend.mockResolvedValue({
      trailList: [
        {
          Name: 'main',
          CloudWatchLogsLogGroupArn:
            'arn:aws:logs:us-east-1:123:log-group:my-ct-logs:*',
        },
      ],
    });
    // Verbatim CIS 4.1 pattern. It matches on UnauthorizedOperation — the
    // errorCode CloudTrail actually emits — not UnauthorizedAccess. Checking
    // for the latter reported this control as missing on accounts whose filter
    // was present and conformant.
    mockLogsSend.mockResolvedValue({
      metricFilters: [
        {
          filterName: 'CIS-UnauthorizedAPICalls',
          filterPattern:
            '{ ($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*") }',
          logGroupName: 'my-ct-logs',
          metricTransformations: [
            { metricName: 'UnauthorizedAPICalls', metricNamespace: 'CIS' },
          ],
        },
      ],
    });

    const findings = await scan();

    // The filter is recognised, so no "metric filter missing" finding. The
    // separate "alarm missing" finding is still expected — this mock
    // deliberately configures no alarm — which is what makes this assertion
    // specific to the keyword match rather than to CIS 4.1 as a whole.
    expect(
      findings.find((f) =>
        f.title.includes('Unauthorized API calls — metric filter missing'),
      ),
    ).toBeUndefined();
    expect(
      findings.find((f) =>
        f.title.includes('Unauthorized API calls — alarm missing'),
      ),
    ).toBeDefined();
  });

  it('returns the prerequisite finding when no trail integrates with CloudWatch Logs', async () => {
    mockTrailSend.mockResolvedValue({
      trailList: [{ Name: 'main' }], // no CloudWatchLogsLogGroupArn
    });

    const findings = await scan();
    expect(findings).toHaveLength(1);
    expect(findings[0].title).toMatch(/not integrated with CloudWatch Logs/i);
  });

  it('falls back to a generic instruction when DescribeTrails is denied', async () => {
    // DescribeTrails throws (e.g. missing cloudtrail:DescribeTrails) -> the log
    // group stays unknown, so the finding keeps the generic text rather than a
    // wrong name. (Not the customer's case, but must not crash or fabricate.)
    mockTrailSend.mockRejectedValue(new Error('AccessDenied'));
    mockLogsSend.mockResolvedValue({ metricFilters: [] });

    const findings = await scan();
    const missing = findings.find((f) =>
      f.title.includes('metric filter missing'),
    );
    expect(missing).toBeDefined();
    expect(missing!.evidence?.cloudWatchLogGroupName).toBeUndefined();
    expect(missing!.remediation).toContain("CloudWatch Logs log group");
  });
});

describe('regionFromArn', () => {
  it('extracts the region from a CloudWatch Logs ARN', () => {
    expect(
      regionFromArn(
        'arn:aws:logs:us-east-1:580772532220:log-group:/aws/cloudtrail/anyray-org-trail:*',
      ),
    ).toBe('us-east-1');
  });

  it('returns null for a missing or malformed ARN', () => {
    expect(regionFromArn(undefined)).toBeNull();
    expect(regionFromArn('not-an-arn')).toBeNull();
    expect(regionFromArn('arn:aws:logs::123:log-group:x')).toBeNull();
  });

  it('pairs with logGroupNameFromArn on the same ARN', () => {
    const arn =
      'arn:aws:logs:eu-central-1:1234:log-group:/aws/cloudtrail/t:*';
    expect(regionFromArn(arn)).toBe('eu-central-1');
    expect(logGroupNameFromArn(arn)).toBe('/aws/cloudtrail/t');
  });
});
