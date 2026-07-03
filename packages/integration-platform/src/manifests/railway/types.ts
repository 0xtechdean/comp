/**
 * Railway GraphQL API response types.
 *
 * Railway exposes a single GraphQL endpoint (https://backboard.railway.com/graphql/v2).
 * Only the fields the security checks read are modelled here — the real schema is
 * far larger. Field names/shapes were verified against the live API.
 */

/** The Railway account the connected token authenticates as (`me`). */
export interface RailwayViewer {
  id: string;
  email: string | null;
  name: string | null;
  /** TOTP/SMS two-factor enabled on the account. */
  has2FA: boolean;
  /** Passkeys count as a strong second factor. */
  hasPasskeys: boolean;
}

/** A Railway workspace (team/account boundary that owns projects and members). */
export interface RailwayWorkspace {
  id: string;
  name: string;
  /** Whether the workspace forces every member to enrol in 2FA. */
  has2FAEnforcement: boolean;
  /** Whether SAML SSO is configured for the workspace. */
  hasSAML: boolean;
  projectCount: number | null;
  /** Emails of members who have NOT enrolled in 2FA. `[String!]!` in the schema. */
  usersWithout2FA: string[];
}

/** Relay-style connection wrapper Railway uses for lists. */
export interface RailwayConnection<T> {
  edges: Array<{ node: T }>;
}

export interface RailwayEnvironment {
  id: string;
  name: string;
  isEphemeral: boolean | null;
}

export interface RailwayService {
  id: string;
  name: string;
}

export interface RailwayProject {
  id: string;
  name: string;
  /** Public projects expose config/metadata to anyone with the link. */
  isPublic: boolean;
  environments?: RailwayConnection<RailwayEnvironment>;
  services?: RailwayConnection<RailwayService>;
}

export interface RailwayWorkspaceWithProjects {
  id: string;
  name: string;
  projects?: RailwayConnection<RailwayProject>;
}
