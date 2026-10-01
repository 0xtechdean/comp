import { extractDomain, partitionVendorsDueForRefresh } from './refresh-due';

describe('extractDomain', () => {
  it('normalizes protocol, www and case', () => {
    expect(extractDomain('https://www.BitDefender.com/path')).toBe(
      'bitdefender.com',
    );
    expect(extractDomain('openai.com')).toBe('openai.com');
  });

  it('returns null for empty or unparseable input', () => {
    expect(extractDomain(null)).toBeNull();
    expect(extractDomain('  ')).toBeNull();
    expect(extractDomain('http://')).toBeNull();
  });
});

describe('partitionVendorsDueForRefresh', () => {
  const vendors = [
    { name: 'WorkOS', website: 'https://workos.com' },
    { name: 'Bitdefender', website: 'https://www.bitdefender.com' },
    { name: 'OpenAI', website: 'https://openai.com' },
    { name: 'Broken', website: 'not a url' },
  ];

  it('skips vendors whose domain was assessed recently, matching across www/protocol variants', () => {
    const { due, skipped } = partitionVendorsDueForRefresh({
      vendors,
      recentlyAssessedWebsites: [
        'workos.com',
        'https://bitdefender.com/trust',
        null,
      ],
    });

    expect(skipped.map((v) => v.name)).toEqual(['WorkOS', 'Bitdefender']);
    // Unparseable websites are never skipped — the task decides what to do with them.
    expect(due.map((v) => v.name)).toEqual(['OpenAI', 'Broken']);
  });

  it('refreshes every vendor when nothing was assessed recently', () => {
    const { due, skipped } = partitionVendorsDueForRefresh({
      vendors,
      recentlyAssessedWebsites: [],
    });
    expect(due).toHaveLength(4);
    expect(skipped).toHaveLength(0);
  });
});
