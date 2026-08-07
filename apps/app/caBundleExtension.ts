import type { BuildContext, BuildExtension, BuildManifest } from '@trigger.dev/build';
import { existsSync } from 'node:fs';
import { cp, mkdir } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';

// Path relative to the monorepo root (apps/api or apps/app → ../../packages/db/certs/...)
const BUNDLE_RELATIVE_FROM_APP = '../../packages/db/certs/rds-global-bundle.pem';
const BUNDLE_DEST_REL = 'certs/rds-global-bundle.pem';
const BUNDLE_URL = 'https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem';

function findBundleSrc(workingDir: string): string | undefined {
  // Walk up from workingDir to find the cert — handles both normal checkouts and git worktrees
  // where workspaceDir points to the main worktree root (wrong for us).
  const candidates = [
    resolve(workingDir, BUNDLE_RELATIVE_FROM_APP),
    resolve(workingDir, '../packages/db/certs/rds-global-bundle.pem'),
    resolve(workingDir, 'packages/db/certs/rds-global-bundle.pem'),
  ];

  return candidates.find((c) => existsSync(c));
}

/**
 * The bundle is gitignored (`*.pem`), so it is absent from any fresh clone, CI
 * runner or git worktree. Make the message say how to fix it rather than only
 * what went wrong.
 */
function missingBundleError(workingDir: string): Error {
  return new Error(
    `CABundleExtension: rds-global-bundle.pem not found. Searched relative to ${workingDir}. ` +
      `The bundle is gitignored, so a fresh clone or CI runner will not have it. Fetch it with: ` +
      `curl -o packages/db/certs/rds-global-bundle.pem ${BUNDLE_URL}`,
  );
}

export function caBundleExtension(): BuildExtension {
  // Resolved once at build start and reused on completion, so the env var and
  // the file on disk can never disagree with each other.
  let bundleSrc: string | undefined;

  return {
    name: 'CABundleExtension',
    onBuildStart: (context) => {
      bundleSrc = findBundleSrc(context.workingDir);

      // Fail BEFORE registering anything. Previously the env var was added here
      // unconditionally while the copy happened in onBuildComplete — so when the
      // bundle was missing, the extension threw *after* the layer was already
      // registered. The Trigger CLI logs that failure but still finishes and
      // prints "Successfully deployed", leaving a worker whose
      // NODE_EXTRA_CA_CERTS points at a file that was never written. Node then
      // logs `Ignoring extra certs ... load failed` on every single start.
      //
      // Throwing here aborts before the image is built rather than after a
      // success line. And if the CLI swallows this the way it swallowed the
      // onBuildComplete throw, the result is still correct: no env var and no
      // cert, so the DB client falls through to Node's default trust store,
      // which is what `resolveSslConfig` in @trycompai/db already relies on.
      if (!bundleSrc) {
        throw missingBundleError(context.workingDir);
      }

      // Real OS env var at task spawn time — verified flow:
      //   addLayer.deploy.env → manifest.deploy.sync.env → syncEnvVarsWithServer →
      //   taskRunProcessProvider injects into worker env before Node TLS init.
      context.addLayer({
        id: 'ca-bundle-env',
        deploy: {
          env: { NODE_EXTRA_CA_CERTS: `/app/${BUNDLE_DEST_REL}` },
          override: true,
        },
      });
    },
    onBuildComplete: async (context: BuildContext, manifest: BuildManifest) => {
      // Re-resolve rather than trusting the closure alone: onBuildStart may have
      // been skipped or the file removed mid-build.
      const src = bundleSrc ?? findBundleSrc(context.workingDir);
      if (!src) {
        throw missingBundleError(context.workingDir);
      }
      const dest = join(manifest.outputPath, BUNDLE_DEST_REL);
      await mkdir(dirname(dest), { recursive: true });
      await cp(src, dest);
      context.logger.log(`Copied RDS CA bundle to ${BUNDLE_DEST_REL}`);
    },
  };
}
