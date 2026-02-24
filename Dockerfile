# ─────────────────────────────────────────────────────────────
# FTH Document Intelligence Engine — Production Container
#
# Multi-stage build:
#   Stage 1: Install dependencies + compile TypeScript
#   Stage 2: Lean runtime with compiled JS only
#
# Runs as non-root user (fth) for security.
# Persists ledger/vault data via mounted volume.
# ─────────────────────────────────────────────────────────────

# ── Stage 1: Build ────────────────────────────────────────────
FROM node:22-bookworm-slim AS builder

WORKDIR /build

# Install OS dependencies for native modules (sharp, puppeteer, tesseract)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    build-essential \
    libvips-dev \
    chromium \
    && rm -rf /var/lib/apt/lists/*

# Copy package files first (cache layer)
COPY package.json package-lock.json tsconfig.json ./

# Install all dependencies (including devDependencies for tsc)
RUN npm ci

# Copy source code
COPY app.ts ./
COPY agreements/ ./agreements/
COPY archive/ ./archive/
COPY batch/ ./batch/
COPY export/ ./export/
COPY gateway/ ./gateway/
COPY governance/ ./governance/
COPY ingest/ ./ingest/
COPY ipfs/ ./ipfs/
COPY parser/ ./parser/
COPY perimeter/ ./perimeter/
COPY registry/ ./registry/
COPY research/ ./research/
COPY schema/ ./schema/
COPY sdc/ ./sdc/
COPY signature/ ./signature/
COPY sovereign/ ./sovereign/
COPY styles/ ./styles/
COPY telecom/ ./telecom/
COPY test/ ./test/
COPY transform/ ./transform/
COPY web/ ./web/

# Compile TypeScript
RUN npx tsc

# ── Stage 2: Runtime ──────────────────────────────────────────
FROM node:22-bookworm-slim AS runtime

# Install runtime OS dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libvips42 \
    chromium \
    fonts-liberation \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Puppeteer: use system Chromium
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

# Create non-root user
RUN groupadd -r fth && useradd -r -g fth -m -d /home/fth fth

WORKDIR /app

# Copy compiled output + production dependencies
COPY --from=builder /build/dist/ ./dist/
COPY --from=builder /build/node_modules/ ./node_modules/
COPY --from=builder /build/package.json ./

# Copy static assets (styles, schemas, web templates)
COPY --from=builder /build/styles/ ./styles/
COPY --from=builder /build/schema/ ./schema/
COPY --from=builder /build/web/ ./web/

# Create data directories (mounted as volumes in production)
RUN mkdir -p /app/.doc-engine /app/input /app/output /app/backups \
    && chown -R fth:fth /app

# Switch to non-root user
USER fth

# Healthcheck — verifies the process is running
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:3001/health || exit 1

# Expose service ports
# 3001 = Sovereign Portal
# 3002 = Signing Gateway
# 3003 = Secure Viewer
# 3004 = SCA Webhook
EXPOSE 3001 3002 3003 3004

# Default: run the engine
ENTRYPOINT ["node", "dist/app.js"]
