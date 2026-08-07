/**
 * Runs before any module is loaded, for every unit spec.
 *
 * The Prisma client module (`prisma/client.ts`) decides its TLS strategy at
 * import time and throws outright for a remote Postgres with neither
 * NODE_EXTRA_CA_CERTS nor PRISMA_ALLOW_INSECURE_TLS set. That is the right
 * behaviour for a booting server, but it made the unit suite depend on whatever
 * DATABASE_URL the developer happened to have exported: anyone pointed at a
 * hosted database could not run the tests at all, and a dozen suites died on
 * import with "Refusing to connect to a non-local Postgres".
 *
 * Unit specs never talk to a real database — the ones that touch it mock '@db'.
 * Prisma also connects lazily, so constructing a client against this address
 * opens no socket. Pinning a localhost URL here makes the suite hermetic and
 * identical on every machine and in CI.
 */
process.env.DATABASE_URL =
  'postgresql://test:test@localhost:5432/test?schema=public';
