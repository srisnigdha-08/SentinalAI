# SentinelAI backend (Express + Socket.IO). The honeypot collector lives outside backend/, so the build
# context is the repository root (see docker-compose.yml).
FROM node:24-alpine

ENV NODE_ENV=production
WORKDIR /app/backend

COPY backend/package.json backend/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

COPY backend/ ./
COPY honeypot/collectors /app/honeypot/collectors

RUN mkdir -p /app/backend/logs && chown -R node:node /app/backend/logs
USER node

EXPOSE 5000
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=5 \
  CMD node -e "fetch('http://127.0.0.1:5000/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "server.js"]
