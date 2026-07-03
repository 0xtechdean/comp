import type { IntegrationCheck } from '../../../types';
import { PROJECTS_QUERY, RAILWAY_GRAPHQL_ENDPOINT } from '../queries';
import type { RailwayProject, RailwayWorkspaceWithProjects } from '../types';

/**
 * Railway Project Inventory
 *
 * Records every project with its environments and service count as passing
 * evidence. This is an asset-inventory control (SOC 2 CC-series) rather than a
 * pass/fail security gate, so it only emits passing results — one per project.
 */
export const projectInventoryCheck: IntegrationCheck = {
  id: 'railway-project-inventory',
  name: 'Railway project inventory',
  description:
    'Records the Railway projects, environments, and services in scope as audit evidence.',
  defaultSeverity: 'info',
  service: 'exposure',

  run: async (ctx) => {
    ctx.log('Building Railway project inventory');
    const { me } = await ctx.graphql<{
      me: { workspaces: RailwayWorkspaceWithProjects[] };
    }>(PROJECTS_QUERY, undefined, { endpoint: RAILWAY_GRAPHQL_ENDPOINT });

    const workspaces = me.workspaces ?? [];

    for (const ws of workspaces) {
      const projects: RailwayProject[] = (ws.projects?.edges ?? []).map(
        (e) => e.node,
      );

      for (const project of projects) {
        const environments = (project.environments?.edges ?? []).map(
          (e) => e.node.name,
        );
        const serviceNames = (project.services?.edges ?? []).map(
          (e) => e.node.name,
        );

        ctx.pass({
          title: `Project "${project.name}" (${serviceNames.length} service${serviceNames.length === 1 ? '' : 's'})`,
          description:
            `Workspace "${ws.name}" · environments: ${environments.join(', ') || 'none'} · ` +
            `services: ${serviceNames.join(', ') || 'none'}.`,
          resourceType: 'railway-project',
          resourceId: project.id,
          evidence: {
            serviceId: 'exposure',
            findingKey: 'railway-project-inventory',
            workspace: ws.name,
            workspaceId: ws.id,
            project: project.name,
            isPublic: project.isPublic,
            environments,
            services: serviceNames,
            checkedAt: new Date().toISOString(),
          },
        });
      }
    }
  },
};
