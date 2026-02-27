# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Install deps (including dev for build)
COPY package.json package-lock.json* ./
RUN npm ci

# Prisma schema and config for generate
COPY src/prisma ./src/prisma
COPY src/prisma.config.ts ./
RUN npx prisma generate --schema=src/prisma/schema.prisma

# Rest of source and build
COPY tsconfig.json ./
COPY src ./src
# Ensure Prisma-generated imports use .js for Node ESM (avoids ERR_MODULE_NOT_FOUND .ts at runtime)
RUN for f in $(find /app/src/generated -name "*.ts"); do sed -i 's/\.ts"/.js"/g; s/\.ts'"'"'/.js'"'"'/g' "$f"; done
RUN npm run build

# Production stage
FROM node:20-alpine AS runner

WORKDIR /app

# Production deps only
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# Prisma schema + migrations (for migrate deploy at startup)
COPY src/prisma ./src/prisma
COPY src/prisma.config.ts ./

# Built app and generated Prisma client from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/src/generated ./src/generated

# Run as non-root
RUN addgroup -g 1001 -S nodejs && adduser -S nodejs -u 1001
RUN chown -R nodejs:nodejs /app
USER nodejs

EXPOSE 3000

# Migrate then start (migrate uses DATABASE_URL from env at runtime)
CMD ["sh", "-c", "npx prisma migrate deploy --schema=src/prisma/schema.prisma && node dist/server.js"]
