import { afterEach, describe, expect, it, vi } from 'vitest';

import { isQuestionnaireFeatureEnabled } from './questionnaire-feature';

describe('isQuestionnaireFeatureEnabled', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('returns true when the PostHog flag is true', () => {
    expect(isQuestionnaireFeatureEnabled({ 'ai-vendor-questionnaire': true })).toBe(true);
  });

  it('returns false when the flag is missing (e.g. PostHog not configured)', () => {
    expect(isQuestionnaireFeatureEnabled({})).toBe(false);
  });

  it('returns false when the flag is false', () => {
    expect(isQuestionnaireFeatureEnabled({ 'ai-vendor-questionnaire': false })).toBe(false);
  });

  it('does not treat a truthy string flag value as enabled', () => {
    expect(isQuestionnaireFeatureEnabled({ 'ai-vendor-questionnaire': 'true' })).toBe(false);
  });

  it('force-enables via ENABLE_AI_QUESTIONNAIRE=true even when the flag is off', () => {
    vi.stubEnv('ENABLE_AI_QUESTIONNAIRE', 'true');
    expect(isQuestionnaireFeatureEnabled({})).toBe(true);
    expect(isQuestionnaireFeatureEnabled({ 'ai-vendor-questionnaire': false })).toBe(true);
  });

  it('ignores non-"true" values of the env override', () => {
    vi.stubEnv('ENABLE_AI_QUESTIONNAIRE', '1');
    expect(isQuestionnaireFeatureEnabled({})).toBe(false);
  });
});
