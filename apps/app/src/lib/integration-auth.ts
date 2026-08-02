/**
 * Auth strategies whose connect flow is a redirect out to the provider and
 * back, rather than a form the user fills in here.
 *
 * OAuth sends the user to an authorization page; a GitHub App sends them to an
 * installation page. Both come back to an API callback that creates the
 * connection and stores credentials, so the UI treats them identically — it
 * just needs a URL to navigate to.
 *
 * Anything else (api_key, basic, custom) collects credentials inline instead.
 * Getting this wrong is not a cosmetic bug: the inline path creates an empty
 * connection row that never receives credentials.
 */
export const usesRedirectConnectFlow = (authType?: string): boolean =>
  authType === 'oauth2' || authType === 'github_app';
