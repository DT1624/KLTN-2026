# Giao diện — P7 (13/11/2026). frontend/.env chỉ chứa thông số chuỗi công khai (VITE_*),
# đồng bộ từ chain.env bằng scripts/sync-chain-env.sh, nên được đưa vào lúc build.
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npx vite build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
