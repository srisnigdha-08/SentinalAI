# SentinelAI backend (Express + Socket.IO). The honeypot collector lives outside backend/, so the build
# context is the repository root (see docker-compose.yml).
FROM node:24-alpine@sha256:a34ab6d7f6f4813f4d0c5469d74685604b962fbdbf5793a7bc7b4998ecb867c8

ENV NODE_ENV=production
WORKDIR /app/backend

COPY backend/package.json backend/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

# The server runs with node alone. Removing the package managers from the final image also removes the vulnerable
# undici and brace-expansion copies that exist only inside npm.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-* \
  /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg

COPY backend/ ./
COPY honeypot/collectors /app/honeypot/collectors

RUN mkdir -p /app/backend/logs && chown -R node:node /app/backend/logs
USER node

EXPOSE 5000
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:5000/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.js"]
