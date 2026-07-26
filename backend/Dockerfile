ARG NODE_IMAGE
FROM ${NODE_IMAGE} AS build
WORKDIR /src
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY patches ./patches
COPY backend/package.json ./backend/package.json
COPY web/package.json ./web/package.json
RUN corepack enable && pnpm install --filter '*api' --frozen-lockfile
COPY backend ./backend
COPY migrations ./migrations
RUN pnpm --filter '*api' run build

FROM ${NODE_IMAGE}
WORKDIR /app
ARG BUILD_MARKER
LABEL org.dsa-signal.build-marker=$BUILD_MARKER
ENV NODE_ENV=production
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY patches ./patches
COPY backend/package.json ./backend/package.json
COPY web/package.json ./web/package.json
RUN corepack enable && pnpm install --filter '*api' --prod --frozen-lockfile
COPY --from=build /src/backend/dist ./backend/dist
USER node
WORKDIR /app/backend
EXPOSE 8080
CMD ["node", "dist/index.js"]
