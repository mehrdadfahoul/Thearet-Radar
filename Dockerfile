# ==========================================
# Stage 1: Build Frontend SPA
# ==========================================
FROM node:22-alpine AS frontend-builder
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

# ==========================================
# Stage 2: Build Backend TypeScript
# ==========================================
FROM node:22-alpine AS backend-builder
WORKDIR /app/backend

COPY backend/package*.json ./
RUN npm ci

COPY backend/ ./
RUN npm run build

# Prune dev dependencies for lean production image
RUN npm prune --production

# ==========================================
# Stage 3: Production Runner (Lean Node.js)
# ==========================================
FROM node:22-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=4000

# Install curl for container health check
RUN apk add --no-cache curl

# Copy backend dependencies & compiled code
COPY --from=backend-builder /app/backend/node_modules ./backend/node_modules
COPY --from=backend-builder /app/backend/dist ./backend/dist
COPY --from=backend-builder /app/backend/package.json ./backend/package.json

# Copy frontend static build so Express can serve both API & UI on single port
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Expose unified Cyber Ops Platform Port
EXPOSE 4000

# Container Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -f http://localhost:4000/api/health || exit 1

WORKDIR /app/backend
CMD ["node", "dist/server.js"]
