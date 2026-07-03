/**
 * GraphQL queries + endpoint shared by the Railway checks.
 *
 * Railway's public API lives at a single POST endpoint; `ctx.graphql` defaults to
 * `${baseUrl}/graphql`, so every call passes this explicit `/graphql/v2` endpoint.
 */

export const RAILWAY_GRAPHQL_ENDPOINT = 'https://backboard.railway.com/graphql/v2';

/** Account-level MFA posture for the token owner. */
export const ACCOUNT_QUERY = /* GraphQL */ `
  query CompAccountMfa {
    me {
      id
      email
      name
      has2FA
      hasPasskeys
    }
  }
`;

/** Workspace-level 2FA enforcement + the list of members missing 2FA. */
export const WORKSPACES_QUERY = /* GraphQL */ `
  query CompWorkspaces {
    me {
      workspaces {
        id
        name
        has2FAEnforcement
        hasSAML
        projectCount
        usersWithout2FA
      }
    }
  }
`;

/** Projects (grouped by workspace) with visibility, environments, and services. */
export const PROJECTS_QUERY = /* GraphQL */ `
  query CompProjects {
    me {
      workspaces {
        id
        name
        projects {
          edges {
            node {
              id
              name
              isPublic
              environments {
                edges {
                  node {
                    id
                    name
                    isEphemeral
                  }
                }
              }
              services {
                edges {
                  node {
                    id
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
  }
`;
