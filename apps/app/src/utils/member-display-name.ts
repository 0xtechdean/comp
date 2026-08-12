/**
 * Resolve a person's display name for UI labels and tables.
 *
 * `User.name` is a non-nullable column, so anyone invited but not yet
 * onboarded carries `''` rather than `null`. That makes `user.name ?? email`
 * a trap: `??` only falls back on null/undefined, so the empty string sails
 * straight through and renders a bare label (e.g. "Person:" with no one after
 * it). Every fallback here is emptiness-aware, and trims first so a
 * whitespace-only name can't win either.
 *
 * Prefer this over hand-rolling `name || email` at each call site.
 */
export function memberDisplayName(
  user: { name?: string | null; email?: string | null } | null | undefined,
  fallback = 'Unknown',
): string {
  return user?.name?.trim() || user?.email?.trim() || fallback;
}
