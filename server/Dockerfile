# Build stage. Only produces node_modules: there is no compile step, because the server runs its
# TypeScript sources directly under Node's native type stripping.
FROM node:24-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# Runtime stage. Distroless has no shell and no package manager, which removes most of what an
# attacker would reach for after a remote code execution bug. The nonroot tag runs as uid 65532.
FROM gcr.io/distroless/nodejs24-debian12:nonroot
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src

ENV NODE_ENV=production
ENV PORT=8080
EXPOSE 8080

# Distroless carries no curl and no shell, so the check has to be node itself.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8080/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]

# The heap cap sits at roughly 75 percent of the container limit in docker-compose.yml, so V8 does
# its own garbage collection work before the kernel OOM killer does something blunter.
CMD ["--max-old-space-size=384", "src/index.ts"]
