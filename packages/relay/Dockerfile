# syntax=docker/dockerfile:1
# Copyright 2026 Ix Infrastructure Inc.
#
# The open Peer2Peer v3 relay. Build from the repository root (the relay
# depends on packages/core by path):
#
#   docker build -f packages/relay/Dockerfile -t peer2peer/relay .
#   docker run -p 8080:8080 -v p2p-relay:/data -e RELAY_URL=wss://relay.example.org/v3 peer2peer/relay
#
# Runs as the distroless `nonroot` user (65532) with its database in /data.
# See docs/run-a-relay.md.
#
# Multi-arch: every base image below is pinned to its multi-arch index digest
# (linux/amd64, linux/arm64, and more), so the same Dockerfile builds for x86
# servers and arm64 boards (Jetson Nano, Raspberry Pi 4/5):
#
#   docker buildx build --platform linux/arm64,linux/amd64 \
#     -f packages/relay/Dockerfile -t registry.example.org/peer2peer/relay:<tag> --push .
#   docker buildx build --platform linux/arm64 \
#     -f packages/relay/Dockerfile -t peer2peer/relay:arm64 -o type=docker,dest=relay-arm64.tar .
#
# The build and prod stages run on the BUILD machine's platform: they only
# compile TypeScript and install pure-JavaScript dependencies (no native
# addons, and npm ci runs with --ignore-scripts in prod), so their output is
# the same on every platform and a cross-build needs no emulation. Only the
# runtime stage is the target platform, and it has no RUN steps. If a
# dependency with a native addon is ever added, drop `--platform=$BUILDPLATFORM`
# from the prod stage so it installs for the target.

# ---- build: compile core and relay -----------------------------------------
FROM --platform=$BUILDPLATFORM node:22.23.2-bookworm-slim@sha256:48e4b67d85f87bd551df43704e24d252f56cc5f8e9718841aace50f19948f0f9 AS build
WORKDIR /src
COPY packages/core/package.json packages/core/package-lock.json packages/core/
RUN cd packages/core && npm ci --no-audit --no-fund
COPY packages/relay/package.json packages/relay/package-lock.json packages/relay/
RUN cd packages/relay && npm ci --no-audit --no-fund
COPY packages/core/ packages/core/
COPY packages/relay/ packages/relay/
RUN cd packages/core && npm run build && cd ../relay && npm run build

# ---- prod: production dependencies only ------------------------------------
FROM --platform=$BUILDPLATFORM node:22.23.2-bookworm-slim@sha256:48e4b67d85f87bd551df43704e24d252f56cc5f8e9718841aace50f19948f0f9 AS prod
WORKDIR /src
COPY packages/core/package.json packages/core/package-lock.json packages/core/
COPY packages/relay/package.json packages/relay/package-lock.json packages/relay/
RUN cd packages/core && npm ci --omit=dev --ignore-scripts --no-audit --no-fund \
 && cd ../relay && npm ci --omit=dev --ignore-scripts --no-audit --no-fund
COPY --from=build /src/packages/core/dist packages/core/dist
COPY --from=build /src/packages/relay/dist packages/relay/dist
RUN mkdir -p /data

# ---- runtime: the target platform (multi-arch index digest) ---------------
FROM gcr.io/distroless/nodejs22-debian12:nonroot@sha256:13593b7570658e8477de39e2f4a1dd25db2f836d68a0ba771251572d23bb4f8e
LABEL org.opencontainers.image.title="peer2peer-relay" \
      org.opencontainers.image.description="Open Peer2Peer v3 relay: store-and-forward for end-to-end encrypted envelopes" \
      org.opencontainers.image.source="https://github.com/ix-infrastructure/Peer2Peer" \
      org.opencontainers.image.licenses="Apache-2.0"
WORKDIR /app
COPY --from=prod /src/packages/core /app/packages/core
COPY --from=prod /src/packages/relay /app/packages/relay
COPY --from=prod --chown=65532:65532 /data /data
# node:sqlite still prints an ExperimentalWarning on Node 22; it is stable for our use.
# On a small board, run with RELAY_PRESET=small and append
# --max-old-space-size=384 to NODE_OPTIONS (docs/run-a-relay-on-any-machine.md).
ENV NODE_ENV=production \
    NODE_OPTIONS=--disable-warning=ExperimentalWarning \
    PORT=8080 \
    DB_PATH=/data/relay.db
VOLUME ["/data"]
EXPOSE 8080
USER 65532:65532
WORKDIR /app/packages/relay
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD ["/nodejs/bin/node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/healthz').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"]
CMD ["dist/bin.js"]
