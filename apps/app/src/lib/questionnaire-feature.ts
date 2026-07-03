import 'server-only';

/**
 * Whether the AI vendor questionnaire feature (upload + auto-answer) is enabled.
 *
 * Normally driven by the PostHog `ai-vendor-questionnaire` flag. Self-hosted
 * instances that don't run PostHog (so `getFeatureFlags` returns `{}`) can force
 * the feature on with the `ENABLE_AI_QUESTIONNAIRE=true` environment variable.
 */
export function isQuestionnaireFeatureEnabled(
  flags: Record<string, string | boolean>,
): boolean {
  if (process.env.ENABLE_AI_QUESTIONNAIRE === 'true') return true;
  return flags['ai-vendor-questionnaire'] === true;
}
