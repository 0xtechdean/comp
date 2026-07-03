# =============================================================================
# Railway build for the `app` service.
#
# The root Dockerfile is multi-target and its TERMINAL stage is `portal`, which
# is what Railway builds by default. This file mirrors the root Dockerfile's
# `deps` -> `app-builder` -> `app` path so the app's production image is the
# terminal stage. Keep in sync with ./Dockerfile (app stages).
# =============================================================================

# =============================================================================
# STAGE 1: Dependencies - Install and cache workspace dependencies
# =============================================================================
FROM oven/bun:1.2.8 AS deps

WORKDIR /app

# Prisma's query engine needs openssl/libssl at generate time; the bun
# Debian-slim base ships without it, so install it before any prisma generate.
RUN apt-get update && apt-get install -y --no-install-recommends openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Copy workspace configuration
COPY package.json bun.lock ./

# Copy package.json for ALL workspace packages so bun can resolve the full
# workspace graph (apps/app depends transitively on db/auth/company/billing/etc.
# via workspace:* — every referenced member must be present).
COPY packages/analytics/package.json ./packages/analytics/
COPY packages/auth/package.json ./packages/auth/
COPY packages/billing/package.json ./packages/billing/
COPY packages/company/package.json ./packages/company/
COPY packages/db/package.json ./packages/db/
COPY packages/device-agent/package.json ./packages/device-agent/
COPY packages/docs/package.json ./packages/docs/
COPY packages/email/package.json ./packages/email/
COPY packages/framework-editor-cli/package.json ./packages/framework-editor-cli/
COPY packages/integration-platform/package.json ./packages/integration-platform/
COPY packages/integrations/package.json ./packages/integrations/
COPY packages/kv/package.json ./packages/kv/
COPY packages/tsconfig/package.json ./packages/tsconfig/
COPY packages/ui/package.json ./packages/ui/
COPY packages/utils/package.json ./packages/utils/

# Copy app package.json files
COPY apps/app/package.json ./apps/app/
COPY apps/portal/package.json ./apps/portal/

# Install all dependencies
RUN PRISMA_SKIP_POSTINSTALL_GENERATE=true bun install --ignore-scripts

# =============================================================================
# STAGE 2: App Builder
# =============================================================================
FROM deps AS app-builder

WORKDIR /app

# Copy all source code needed for build
COPY packages ./packages
COPY apps/app ./apps/app

# Bring in node_modules for build and prisma prebuild
COPY --from=deps /app/node_modules ./node_modules

# Build the workspace packages the app imports so @trycompai/* resolve to their
# dist output (the API multistage does the same). `packages/db`'s build also
# generates the Prisma client into node_modules/@prisma/client. Without this,
# `next build` fails with "Module not found: @trycompai/auth|billing|company".
RUN cd packages/db && bun run build
RUN cd packages/auth && bun run build \
 && cd ../integration-platform && bun run build \
 && cd ../email && bun run build \
 && cd ../company && bun run build \
 && cd ../billing && bun run build

# Ensure Next build has required public env at build-time
ARG NEXT_PUBLIC_BETTER_AUTH_URL
ARG NEXT_PUBLIC_PORTAL_URL
ARG NEXT_PUBLIC_POSTHOG_KEY
ARG NEXT_PUBLIC_POSTHOG_HOST
ARG NEXT_PUBLIC_IS_DUB_ENABLED
ARG NEXT_PUBLIC_API_URL
ENV NEXT_PUBLIC_BETTER_AUTH_URL=$NEXT_PUBLIC_BETTER_AUTH_URL \
    NEXT_PUBLIC_PORTAL_URL=$NEXT_PUBLIC_PORTAL_URL \
    NEXT_PUBLIC_POSTHOG_KEY=$NEXT_PUBLIC_POSTHOG_KEY \
    NEXT_PUBLIC_POSTHOG_HOST=$NEXT_PUBLIC_POSTHOG_HOST \
    NEXT_PUBLIC_IS_DUB_ENABLED=$NEXT_PUBLIC_IS_DUB_ENABLED \
    NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL \
    NEXT_TELEMETRY_DISABLED=1 NODE_ENV=production \
    NEXT_OUTPUT_STANDALONE=true \
    NODE_OPTIONS=--max_old_space_size=6144

# Build the app
RUN cd apps/app && SKIP_ENV_VALIDATION=true bun run build:docker

# =============================================================================
# STAGE 3: App Production (terminal stage)
# =============================================================================
FROM node:22-alpine AS app

WORKDIR /app

# Copy Next standalone output
COPY --from=app-builder /app/apps/app/.next/standalone ./
COPY --from=app-builder /app/apps/app/.next/static ./apps/app/.next/static
COPY --from=app-builder /app/apps/app/public ./apps/app/public

EXPOSE 3000
CMD ["node", "apps/app/server.js"]
