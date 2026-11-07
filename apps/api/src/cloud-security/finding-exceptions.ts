import { db } from '@db';

/**
 * Metadata about one active exception. Display surfaces use it to show the
 * documented reason next to a suppressed finding and to offer revoke (which
 * needs the row id) without a second query.
 */
export interface ActiveExceptionInfo {
  id: string;
  reason: string;
}

/**
 * A class exception (`match: prefix`): covers every finding on its connection
 * whose checkId starts with `checkIdPrefix` AND whose resourceId starts with
 * `resourceIdPrefix`. Used for a finding that recurs per resource, such as one
 * secret per deployed stack, where the check key itself carries the resource
 * name and an exact exception would be needed for every new one.
 */
export interface PrefixExceptionRule {
  connectionId: string;
  checkIdPrefix: string;
  resourceIdPrefix: string;
  info: ActiveExceptionInfo;
}

/** Whether a prefix rule covers this finding. Both prefixes must match. */
export function prefixRuleMatches(params: {
  rule: Pick<
    PrefixExceptionRule,
    'connectionId' | 'checkIdPrefix' | 'resourceIdPrefix'
  >;
  connectionId: string;
  checkId: string;
  resourceId: string;
}): boolean {
  const { rule, connectionId, checkId, resourceId } = params;
  return (
    rule.connectionId === connectionId &&
    checkId.startsWith(rule.checkIdPrefix) &&
    resourceId.startsWith(rule.resourceIdPrefix)
  );
}

/**
 * The set of findings — keyed by (connectionId, checkId, resourceId), plus
 * class exceptions matched by prefix — that currently have an ACTIVE exception
 * (not revoked, not expired) for an org.
 *
 * This is the SINGLE source of truth for "is this finding excepted?". Every
 * place that turns a check result into a pass/fail must go through here so an
 * exception is honored consistently:
 *   - the Cloud Tests findings view (cloud-security-query.getFindings)
 *   - the task-check display (task-integrations getTaskCheckRuns)
 *   - the task-check run paths that set task status (manual run-check + the
 *     scheduled Trigger task)
 *
 * Centralizing the key format + the active filter here is deliberate: it's the
 * easy-to-get-wrong part, and duplicating it risks honoring an exception in one
 * surface but not another.
 */
export class ActiveExceptionSet {
  private readonly keys: Set<string>;
  /**
   * Excepted resourceIds grouped by `connectionId::checkId`. Lets a caller
   * count a run's excepted failures with a targeted query instead of loading
   * every result row into memory.
   */
  private readonly resourceIdsByConnCheck: Map<string, Set<string>>;
  /** Exception metadata per canonical key. Optional — evaluation-only callers
   *  build the set from bare keys and never ask for it. */
  private readonly infoByKey: ReadonlyMap<string, ActiveExceptionInfo>;
  /** Class exceptions, matched by prefix after the exact keys miss. */
  private readonly prefixRules: readonly PrefixExceptionRule[];

  constructor(
    keys: Iterable<string>,
    infoByKey?: ReadonlyMap<string, ActiveExceptionInfo>,
    prefixRules: readonly PrefixExceptionRule[] = [],
  ) {
    this.keys = new Set(keys);
    this.infoByKey = infoByKey ?? new Map();
    this.prefixRules = prefixRules;
    this.resourceIdsByConnCheck = new Map();
    for (const key of this.keys) {
      // key = `${connectionId}::${checkId}::${resourceId}`. A resourceId can
      // itself contain "::", so take the first two segments and rejoin the
      // rest — reconstructing exactly the resourceId used to build the key.
      const parts = key.split('::');
      if (parts.length < 3) continue;
      const groupKey = `${parts[0]}::${parts[1]}`;
      const resourceId = parts.slice(2).join('::');
      let ids = this.resourceIdsByConnCheck.get(groupKey);
      if (!ids) {
        ids = new Set();
        this.resourceIdsByConnCheck.set(groupKey, ids);
      }
      ids.add(resourceId);
    }
  }

  /** Canonical key. The only place this format is defined. */
  static key(
    connectionId: string,
    checkId: string,
    resourceId: string,
  ): string {
    return `${connectionId}::${checkId}::${resourceId}`;
  }

  get size(): number {
    return this.keys.size + this.prefixRules.length;
  }

  has(connectionId: string, checkId: string, resourceId: string): boolean {
    return (
      this.keys.has(
        ActiveExceptionSet.key(connectionId, checkId, resourceId),
      ) || this.findPrefixRule(connectionId, checkId, resourceId) !== null
    );
  }

  /**
   * The excepted resourceIds for a (connection, check) pair. Empty when nothing
   * is excepted for that pair — callers use this to skip the count query
   * entirely (the common case: no exceptions).
   */
  exceptedResourceIds(connectionId: string, checkId: string): string[] {
    const ids = this.resourceIdsByConnCheck.get(
      `${connectionId}::${checkId}`,
    );
    return ids ? Array.from(ids) : [];
  }

  /**
   * Resource-id prefixes of the class exceptions that apply to a (connection,
   * check) pair: those on this connection whose check-id prefix the check id
   * starts with. Companion to {@link exceptedResourceIds} for the count query.
   */
  exceptedResourceIdPrefixes(connectionId: string, checkId: string): string[] {
    return this.prefixRules
      .filter(
        (rule) =>
          rule.connectionId === connectionId &&
          checkId.startsWith(rule.checkIdPrefix),
      )
      .map((rule) => rule.resourceIdPrefix);
  }

  /**
   * Metadata (row id + reason) of the active exception covering this finding,
   * or null when none. Null also for sets built without metadata (bare keys) —
   * `has()` stays the authority on whether a finding is excepted.
   */
  infoFor(
    connectionId: string,
    checkId: string,
    resourceId: string,
  ): ActiveExceptionInfo | null {
    return (
      this.infoByKey.get(
        ActiveExceptionSet.key(connectionId, checkId, resourceId),
      ) ??
      this.findPrefixRule(connectionId, checkId, resourceId)?.info ??
      null
    );
  }

  private findPrefixRule(
    connectionId: string,
    checkId: string,
    resourceId: string,
  ): PrefixExceptionRule | null {
    return (
      this.prefixRules.find((rule) =>
        prefixRuleMatches({ rule, connectionId, checkId, resourceId }),
      ) ?? null
    );
  }
}

/**
 * Load active finding exceptions for an org as an {@link ActiveExceptionSet}.
 *
 * Fail-safe: on any DB error this returns an EMPTY set (suppress nothing) so a
 * lookup failure can never hide a real finding — we would rather show a finding
 * the customer excepted than silently pass a genuine one.
 */
export async function loadActiveExceptionSet(
  organizationId: string,
): Promise<ActiveExceptionSet> {
  try {
    const active = await db.findingException.findMany({
      where: {
        organizationId,
        revokedAt: null,
        OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
      },
      select: {
        id: true,
        connectionId: true,
        checkId: true,
        resourceId: true,
        reason: true,
        match: true,
      },
    });
    const infoByKey = new Map<string, ActiveExceptionInfo>();
    const prefixRules: PrefixExceptionRule[] = [];
    for (const e of active) {
      const info = { id: e.id, reason: e.reason };
      if (e.match === 'prefix') {
        prefixRules.push({
          connectionId: e.connectionId,
          checkIdPrefix: e.checkId,
          resourceIdPrefix: e.resourceId,
          info,
        });
        continue;
      }
      infoByKey.set(
        ActiveExceptionSet.key(e.connectionId, e.checkId, e.resourceId),
        info,
      );
    }
    return new ActiveExceptionSet(infoByKey.keys(), infoByKey, prefixRules);
  } catch {
    return new ActiveExceptionSet([]);
  }
}
