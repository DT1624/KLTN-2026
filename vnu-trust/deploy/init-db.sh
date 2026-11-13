#!/usr/bin/env bash
# Nạp db/schema.sql vào Postgres trên host (Neon/Supabase). Chạy MỘT lần trước
# khi bật backend; chạy lại vẫn an toàn vì lược đồ dùng IF NOT EXISTS.
#
#   cp deploy/.env.example deploy/.env   # rồi điền DB_*
#   ./deploy/init-db.sh
set -euo pipefail
cd "$(dirname "$0")"

[ -f .env ] || { echo "Thiếu deploy/.env — chép từ deploy/.env.example rồi điền DB_*"; exit 1; }
set -a; . ./.env; set +a
: "${DB_HOST:?thiếu DB_HOST}" "${DB_NAME:?thiếu DB_NAME}" "${DB_USER:?thiếu DB_USER}" "${DB_PASSWORD:?thiếu DB_PASSWORD}"

export PGHOST=$DB_HOST PGPORT=${DB_PORT:-5432} PGDATABASE=$DB_NAME PGUSER=$DB_USER \
       PGPASSWORD=$DB_PASSWORD PGSSLMODE=${DB_SSLMODE:-require} PGOPTIONS="--client-min-messages=warning"
SCHEMA=$(cd .. && pwd)/db/schema.sql

echo "Nạp lược đồ vào $PGUSER@$PGHOST/$PGDATABASE (sslmode=$PGSSLMODE)"
if command -v psql >/dev/null; then
  psql -v ON_ERROR_STOP=1 -q -f "$SCHEMA"
  psql -At -c "SELECT count(*) || ' bảng' FROM information_schema.tables WHERE table_schema='public'"
elif command -v docker >/dev/null; then
  docker run --rm -i -e PGHOST -e PGPORT -e PGDATABASE -e PGUSER -e PGPASSWORD -e PGSSLMODE -e PGOPTIONS \
    postgres:16-alpine psql -v ON_ERROR_STOP=1 -q -f - <"$SCHEMA"
else
  echo "Cần psql hoặc docker để chạy tập lệnh này"; exit 1
fi
echo "Xong."
