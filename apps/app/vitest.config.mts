import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import tsconfigPaths from 'vite-tsconfig-paths';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [tsconfigPaths({ projects: ['./tsconfig.json'] }), react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test-utils/setup.ts'],
    include: [
      'src/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}',
      'prisma/**/*.{test,spec}.{js,mjs,cjs,ts,mts,cts,jsx,tsx}',
    ],
    exclude: ['node_modules', 'dist', '.next', 'e2e'],
    coverage: {
      reporter: ['text', 'json', 'html'],
      include: ['src/app/(app)/*/security/penetration-tests/**/*.{ts,tsx}'],
      exclude: [
        'node_modules/',
        'src/test-utils/',
        '.trigger/**',
        '.next/**',
        '**/*.d.ts',
        '**/*.config.*',
        '**/mockData/*',
        '**/*.test.{ts,tsx}',
      ],
    },
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, './src'),
      // Listed before '@trycompai/auth': aliases match by prefix, so the barrel
      // entry would otherwise swallow this subpath.
      '@trycompai/auth/participation': resolve(__dirname, '../../packages/auth/src/participation.ts'),
      '@trycompai/auth': resolve(__dirname, '../../packages/auth/src/index.ts'),
      '@trycompai/billing': resolve(__dirname, '../../packages/billing/src/index.ts'),
    },
  },
});
