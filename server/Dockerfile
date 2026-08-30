# ObliWAN server image — Node API + Socket.io, and (from later milestones) the
# CWMP/TR-069 listener, the SNMP trap receiver and the syslog receiver.
# ObliWAN is agentless: there is no Go binary, no MSI and no wizard to build.

# ---- Build stage (shared + server) ----
FROM node:24-alpine AS builder
WORKDIR /app

COPY package.json ./
COPY shared/ ./shared/
RUN cd shared && npm install && npm run build

COPY server/package.json ./server/
RUN cd server && npm install

COPY server/tsconfig.json server/knexfile.ts ./server/
COPY server/src/ ./server/src/
RUN cd server && npm run build

# ---- Production stage ----
FROM node:24-alpine AS production
WORKDIR /app

# openssh-client: the SSH transport (RouterOS /export, DrayTek/Zyxel CLI) and
# SFTP config backups shell out to it.
RUN apk add --no-cache openssh-client

COPY --from=builder /app/shared/package.json ./shared/
COPY --from=builder /app/shared/dist/ ./shared/dist/

COPY --from=builder /app/server/package.json ./server/
COPY package.json ./
RUN cd server && npm install --omit=dev

# dist/ already holds the compiled knexfile.js and db/migrations/*.js —
# index.ts calls db.migrate.latest() at startup.
COPY --from=builder /app/server/dist/ ./server/dist/

COPY server/docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 3001 stays internal to the compose network (nginx proxies it).
EXPOSE 3001/tcp
# Inbound device traffic — these ARE published by the compose files. This is the
# one deviation from the Obli* topology; see docker-compose.yml for the why.
# 162 and 514 are privileged ports: the process runs as root inside the
# container, which is what allows binding them. Do not add a USER directive
# without moving those listeners to high ports and remapping them in compose.
EXPOSE 7547/tcp
EXPOSE 7548/tcp
EXPOSE 162/udp
EXPOSE 514/udp
EXPOSE 514/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD sh -c "wget --no-verbose --tries=1 --spider http://localhost:${PORT:-3001}/health || exit 1"

WORKDIR /app/server
ENTRYPOINT ["/entrypoint.sh"]
CMD ["node", "dist/src/index.js"]
