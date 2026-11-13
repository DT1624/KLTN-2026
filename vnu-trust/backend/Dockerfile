# Backend TypeScript — P7 (13/11/2026). Dùng qua `docker compose --profile app up --build`.
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
WORKDIR /app
# NODE_ENV=production + VERIFY_ONCHAIN=false thì backend tự thoát (quyết định #8).
ENV NODE_ENV=production
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
USER node
EXPOSE 4000
CMD ["node", "dist/server.js"]
