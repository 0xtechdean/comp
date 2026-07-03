import type { IntegrationCheck } from '../../../types';
import { PROJECTS_QUERY, RAILWAY_GRAPHQL_ENDPOINT } from '../queries';
import type { RailwayProject, RailwayWorkspaceWithProjects } from '../types';

/**
 * Railway Public Project Exposure Check
 *
 * A public Railway project exposes its configuration and metadata to anyone with
 * the link. This flags every project whose `isPublic` flag is set, and records a
 * passing result per private project for the audit trail.
 */
export const projectVisibilityCheck: IntegrationCheck = {
  id: 'railway-project-visibility',
  name: 'Railway projects are not publicly exposed',
  description:
    'Checks that no Railway project is marked public (which exposes its config and metadata).',
  defaultSeverity: 'high',
  service: 'exposure',

  run: async (ctx) => {
    ctx.log('Fetching Railway projects and visibility');
    const { me } = await ctx.graphql<{
      me: { workspaces: RailwayWorkspaceWithProjects[] };
    }>(PROJECTS_QUERY, undefined, { endpoint: RAILWAY_GRAPHQL_ENDPOINT });

    const workspaces = me.workspaces ?? [];
    let projectCount = 0;

    for (const ws of workspaces) {
      const projects: RailwayProject[] = (ws.projects?.edges ?? []).map(
        (e) => e.node,
      );
      for (const project of projects) {
        projectCount++;
        const evidence = {
          serviceId: 'exposure',
          findingKey: 'railway-project-visibility',
          workspace: ws.name,
          workspaceId: ws.id,
          project: project.name,
          isPublic: project.isPublic,
          checkedAt: new Date().toISOString(),
        };

        if (project.isPublic) {
          ctx.fail({
            title: `Railway project "${project.name}" is public`,
            description:
              `Project "${project.name}" in workspace "${ws.name}" is publicly visible, exposing its ` +
              'configuration, environments, and metadata to anyone with the link.',
            resourceType: 'railway-project',
            resourceId: project.id,
            severity: 'high',
            remediation:
              'Open the project in Railway → Settings → General and disable public visibility unless it is intentionally a public template.',
            evidence,
          });
        } else {
          ctx.pass({
            title: `Railway project "${project.name}" is private`,
            description: 'The project is not publicly visible.',
            resourceType: 'railway-project',
            resourceId: project.id,
            evidence,
          });
        }
      }
    }

    ctx.log(`Checked visibility for ${projectCount} project(s)`);
  },
};
