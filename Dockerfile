# OpenChamber private relay — standalone Node adapter.
#
#   docker build -t openchamber-relay .
#   docker run -p 8788:8788 openchamber-relay
#
# Optional usage accounting (SQLite):
#   docker run -p 8788:8788 -v relay-data:/data -e RELAY_USAGE_DB=/data/usage.sqlite openchamber-relay
#
# Terminate TLS in front of this container (Caddy/Traefik/nginx) — see deploy/docker-compose.yml.

FROM node:24-alpine

WORKDIR /app

ENV NODE_ENV=production
COPY package.json package-lock.json ./
# tsx is needed at runtime (the server runs from TypeScript sources), so install dev deps too.
RUN npm ci --ignore-scripts

COPY tsconfig.base.json tsconfig.node.json ./
COPY src/core ./src/core
COPY src/node ./src/node
COPY migrations ./migrations

ENV PORT=8788 HOST=0.0.0.0
EXPOSE 8788

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:8788/health || exit 1

USER node

# Exec form + single process so SIGTERM reaches the server and the usage flush runs on shutdown.
CMD ["node", "--import", "tsx", "src/node/server.ts"]
