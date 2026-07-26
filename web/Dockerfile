ARG NODE_IMAGE
ARG NGINX_IMAGE
FROM ${NODE_IMAGE} AS build
WORKDIR /src
ARG VITE_BUILD_MARKER=development
ENV VITE_BUILD_MARKER=$VITE_BUILD_MARKER
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY patches ./patches
COPY backend/package.json ./backend/package.json
COPY web/package.json ./web/package.json
RUN corepack enable && pnpm install --filter '*web' --frozen-lockfile
COPY web ./web
RUN pnpm --filter '*web' run build

FROM ${NGINX_IMAGE}
ARG BUILD_MARKER
LABEL org.dsa-signal.build-marker=$BUILD_MARKER
COPY --from=build /src/web/dist /usr/share/nginx/html
EXPOSE 80
