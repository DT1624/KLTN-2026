#!/usr/bin/env bash
# Dọn tài nguyên.
#
#   ./scripts/clean.sh          dừng mọi dịch vụ + xoá log, tệp tạm, sản phẩm build
#                               (GIỮ image Docker, volume dữ liệu và node_modules để lần sau bật nhanh)
#   ./scripts/clean.sh --all    như trên + xoá volume dữ liệu dev và node_modules (hỏi xác nhận)
. "$(dirname "$0")/lib.sh"

echo "Dừng dịch vụ…"
for s in "$RUN"/*.pid; do [ -e "$s" ] && stop_svc "$(basename "$s" .pid)" && ok "đã dừng $(basename "$s" .pid)"; done
for p in 5173 4000 4001 4010 4011 4097 4098; do stop_port "$p" && ok "đã giải phóng cổng $p"; done
# Lượt kiểm thử bị ngắt giữa chừng có thể để sót CSDL tạm.
psql_c -d postgres -c "DROP DATABASE IF EXISTS vnu_trust_test WITH (FORCE)" >/dev/null 2>&1
if docker ps -q --filter name=$PG_CONTAINER | grep -q .; then
  (cd "$ROOT" && docker compose stop >/dev/null 2>&1) && ok "đã dừng Postgres (dữ liệu giữ trong volume)"
fi

echo "Xoá tệp sinh ra…"
rm -rf "$RUN" "$ROOT/.dev-logs" "$ROOT/backend-go/bin" "$ROOT/backend/dist" "$ROOT/frontend/dist" "$ROOT/contracts/build" \
       "$ROOT"/frontend/*.tsbuildinfo "$ROOT"/frontend/.tmp-*.mjs "$ROOT"/frontend/{p,t,perf-tmp}.mjs
ok "log, bin/, dist/, contracts/build, tệp tạm"

if [ "${1:-}" = "--all" ]; then
  read -r -p "Xoá volume vnu_trust_pgdata (MẤT dữ liệu dev) và node_modules? [y/N] " a
  if [ "$a" = y ]; then
    (cd "$ROOT" && docker compose down -v >/dev/null 2>&1); ok "đã xoá container + volume"
    rm -rf "$ROOT/backend/node_modules" "$ROOT/frontend/node_modules"; ok "đã xoá node_modules"
  fi
fi
