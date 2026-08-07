const mockExistsSync = jest.fn();
jest.mock('node:fs', () => ({ existsSync: (p: string) => mockExistsSync(p) }));

const mockCp = jest.fn();
const mockMkdir = jest.fn();
jest.mock('node:fs/promises', () => ({
  cp: (...a: unknown[]) => mockCp(...a),
  mkdir: (...a: unknown[]) => mockMkdir(...a),
}));

import { caBundleExtension } from '../../caBundleExtension';

const WORKING_DIR = '/repo/apps/api';
const BUNDLE_PATH = '/repo/packages/db/certs/rds-global-bundle.pem';

type Layer = { id: string; deploy?: { env?: Record<string, string> } };

function makeContext() {
  const layers: Layer[] = [];
  return {
    workingDir: WORKING_DIR,
    addLayer: (l: Layer) => layers.push(l),
    logger: {
      log: jest.fn(),
      warn: jest.fn(),
      error: jest.fn(),
      debug: jest.fn(),
    },
    layers,
  };
}

// Only the first candidate — resolve(workingDir, '../../packages/db/certs/...')
// — matches from apps/api; everything else must miss.
const onlyRealBundleExists = (p: string) => p === BUNDLE_PATH;

describe('caBundleExtension', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockMkdir.mockResolvedValue(undefined);
    mockCp.mockResolvedValue(undefined);
  });

  describe('when the bundle is present', () => {
    beforeEach(() => mockExistsSync.mockImplementation(onlyRealBundleExists));

    it('registers NODE_EXTRA_CA_CERTS pointing at the baked-in path', () => {
      const ext = caBundleExtension();
      const ctx = makeContext();

      void ext.onBuildStart?.(ctx as never);

      expect(ctx.layers).toHaveLength(1);
      expect(ctx.layers[0].deploy?.env).toEqual({
        NODE_EXTRA_CA_CERTS: '/app/certs/rds-global-bundle.pem',
      });
    });

    it('copies the bundle into the build output', async () => {
      const ext = caBundleExtension();
      const ctx = makeContext();

      void ext.onBuildStart?.(ctx as never);
      await ext.onBuildComplete?.(
        ctx as never,
        { outputPath: '/out' } as never,
      );

      expect(mockMkdir).toHaveBeenCalledWith('/out/certs', { recursive: true });
      expect(mockCp).toHaveBeenCalledWith(
        BUNDLE_PATH,
        '/out/certs/rds-global-bundle.pem',
      );
    });
  });

  describe('when the bundle is missing', () => {
    beforeEach(() => mockExistsSync.mockReturnValue(false));

    // The regression: the env var used to be registered unconditionally, so a
    // failed copy left the worker pointing at a file that was never written and
    // Node logged "Ignoring extra certs ... load failed" on every start.
    it('does NOT register NODE_EXTRA_CA_CERTS', () => {
      const ext = caBundleExtension();
      const ctx = makeContext();

      expect(() => ext.onBuildStart?.(ctx as never)).toThrow(
        /rds-global-bundle\.pem not found/,
      );
      expect(ctx.layers).toHaveLength(0);
    });

    it('fails at build START, before any image work', () => {
      const ext = caBundleExtension();
      const ctx = makeContext();

      expect(() => ext.onBuildStart?.(ctx as never)).toThrow();
      expect(mockCp).not.toHaveBeenCalled();
    });

    it('also fails on completion, and never copies', async () => {
      const ext = caBundleExtension();
      const ctx = makeContext();

      await expect(
        ext.onBuildComplete?.(ctx as never, { outputPath: '/out' } as never),
      ).rejects.toThrow(/rds-global-bundle\.pem not found/);
      expect(mockCp).not.toHaveBeenCalled();
    });

    it('tells the operator the bundle is gitignored and how to fetch it', () => {
      const ext = caBundleExtension();
      const ctx = makeContext();

      // A fresh clone / CI runner hits this, so the message has to be actionable.
      expect(() => ext.onBuildStart?.(ctx as never)).toThrow(/gitignored/);
      expect(() =>
        caBundleExtension().onBuildStart?.(makeContext() as never),
      ).toThrow(/truststore\.pki\.rds\.amazonaws\.com/);
    });
  });

  it('falls back to the sibling candidate path (git worktree layout)', async () => {
    // resolve('/repo/apps/api', '../packages/db/certs/...') → /repo/apps/packages/...
    const siblingPath = '/repo/apps/packages/db/certs/rds-global-bundle.pem';
    mockExistsSync.mockImplementation((p: string) => p === siblingPath);

    const ext = caBundleExtension();
    const ctx = makeContext();
    void ext.onBuildStart?.(ctx as never);
    await ext.onBuildComplete?.(ctx as never, { outputPath: '/out' } as never);

    expect(ctx.layers).toHaveLength(1);
    expect(mockCp).toHaveBeenCalledWith(
      siblingPath,
      '/out/certs/rds-global-bundle.pem',
    );
  });
});
