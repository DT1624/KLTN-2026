#!/usr/bin/env bash
# Build rồi chạy server. Biến đã đặt sẵn trong môi trường thắng .env (giống dotenv
# bên TS), để dev.sh ghi đè được DB_NAME, hạn mức… khi chạy kiểm thử.
cd "$(dirname "$0")"
if [ -f .env ]; then
  while IFS='=' read -r k v; do
    [[ $k =~ ^[A-Z_][A-Z0-9_]*$ ]] && [ -z "${!k+x}" ] && export "$k=$v"
  done < .env
fi
go build -o ./bin/server ./cmd/server || exit 1
exec ./bin/server
