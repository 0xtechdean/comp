import { memberDisplayName } from './member-display-name';

describe('memberDisplayName', () => {
  it('prefers the name when one is set', () => {
    expect(
      memberDisplayName({ name: 'Ada Lovelace', email: 'ada@example.com' }),
    ).toBe('Ada Lovelace');
  });

  // The regression this helper exists for: `User.name` is non-nullable, so an
  // invited-but-not-onboarded person carries `''`. `??` would return the empty
  // string and render a bare label.
  it('falls back to the email when the name is an empty string', () => {
    expect(memberDisplayName({ name: '', email: 'dimar@example.com' })).toBe(
      'dimar@example.com',
    );
  });

  it('falls back to the email when the name is only whitespace', () => {
    expect(memberDisplayName({ name: '   ', email: 'dimar@example.com' })).toBe(
      'dimar@example.com',
    );
  });

  it('falls back to the email when the name is null', () => {
    expect(memberDisplayName({ name: null, email: 'dimar@example.com' })).toBe(
      'dimar@example.com',
    );
  });

  it('trims a padded name rather than emitting the padding', () => {
    expect(
      memberDisplayName({ name: '  Ada  ', email: 'ada@example.com' }),
    ).toBe('Ada');
  });

  it('uses the default fallback when both name and email are empty', () => {
    expect(memberDisplayName({ name: '', email: '' })).toBe('Unknown member');
  });

  it('uses the default fallback for a null user', () => {
    expect(memberDisplayName(null)).toBe('Unknown member');
    expect(memberDisplayName(undefined)).toBe('Unknown member');
  });

  it('honours a caller-supplied fallback', () => {
    // Export columns pass '' so an unattributed row stays visibly blank
    // rather than claiming an "Unknown member" did the work.
    expect(memberDisplayName(null, '')).toBe('');
    expect(memberDisplayName({ name: '', email: '' }, '')).toBe('');
  });
});
