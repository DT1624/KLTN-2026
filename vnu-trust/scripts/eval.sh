#!/usr/bin/env bash
# Bộ đánh giá mở rộng cho báo cáo (bản rút gọn) — sáu thí nghiệm, xong tự dọn.
#
#   ./scripts/eval.sh            chạy tất cả: .bench/eval/*.json → .bench/eval/tex/*.tex
#   ./scripts/eval.sh --offline  bỏ thí nghiệm F (cần mạng tới fullnode thật)
#   ./scripts/eval.sh --plot     chỉ vẽ lại từ dữ liệu đã có
#
# Cách ly giống test.sh: CSDL riêng `vnu_trust_eval` (tạo mới, xoá khi xong), cổng
# riêng 4020/4021, VERIFY_ONCHAIN=false. Thí nghiệm E tạm ghim CPU cho container
# Postgres bằng `docker update --cpuset-cpus` và trả lại như cũ khi thoát.
# Docker được trả về đúng trạng thái trước khi chạy: nếu trước đó chưa có container
# hay volume thì xoá hẳn (`compose down -v`), nếu có thì chỉ dừng lại.
. "$(dirname "$0")/lib.sh"

EVAL_DB=vnu_trust_eval
OUT="$ROOT/.bench/eval"
TS=http://localhost:4020/api
GO=http://localhost:4021/api
NCPU=$(nproc)
SVC_CPUS=0,1
LOAD_CPUS=2,3
mkdir -p "$OUT"

# node_noble nhưng ghim CPU cho bộ sinh tải (thí nghiệm E)
node_pinned() { # node_pinned <cpus|-> <tệp> [đối số…]
  local cpus=$1 src=$2 tmp="$ROOT/frontend/.tmp-$(basename "$2")" rc; shift 2
  cp "$src" "$tmp" || return 1
  if [ "$cpus" = - ]; then (cd "$ROOT/frontend" && node "$tmp" "$@"); else (cd "$ROOT/frontend" && taskset -c "$cpus" node "$tmp" "$@"); fi
  rc=$?; rm -f "$tmp"; return $rc
}

plot() { (cd "$ROOT" && node scripts/eval/plot.mjs); }
if [ "${1:-}" = "--plot" ]; then plot; exit $?; fi

# ---------------------------------------------------------------- dọn dẹp
HAD_VOLUME=$(docker volume ls -q --filter name=vnu_trust_pgdata | grep -c . || true)
HAD_CONTAINER=$(docker ps -aq --filter name=$PG_CONTAINER | grep -c . || true)
DB_WAS_UP=0; docker exec "$PG_CONTAINER" pg_isready -U "$DB_USER" >/dev/null 2>&1 && DB_WAS_UP=1
CPUSET_BEFORE=""
cleanup() {
  echo; echo "── Dọn dẹp"
  for s in e-ts e-go; do stop_svc "$s" 2>/dev/null; done
  for p in 4020 4021; do stop_port "$p" 2>/dev/null; done
  if docker ps -q --filter name=$PG_CONTAINER | grep -q .; then
    docker update --cpuset-cpus "${CPUSET_BEFORE:-0-$((NCPU - 1))}" "$PG_CONTAINER" >/dev/null 2>&1 && ok "trả lại cpuset của Postgres"
    psql_c -d postgres -c "DROP DATABASE IF EXISTS $EVAL_DB WITH (FORCE)" >/dev/null 2>&1 && ok "đã xoá CSDL $EVAL_DB"
  fi
  if [ "$HAD_VOLUME" = 0 ] && [ "$HAD_CONTAINER" = 0 ]; then
    (cd "$ROOT" && docker compose down -v >/dev/null 2>&1) && ok "trước đó chưa có Postgres: đã xoá container, network, volume"
  elif [ "$DB_WAS_UP" = 0 ]; then
    (cd "$ROOT" && docker compose stop >/dev/null 2>&1) && ok "đã tắt lại Postgres"
  fi
  # state.json chứa khoá riêng của tài khoản thử — không để lại trên đĩa.
  rm -f "$OUT/state.json" "$RUN"/e-*.log "$ROOT"/frontend/.tmp-*.mjs
  rm -rf "$ROOT/backend-go/bin"
  ok "đã xoá tệp trạng thái, log, bin/"
}
trap cleanup EXIT

# ---------------------------------------------------------------- A, B, C: không cần dịch vụ
# SKIP_STATIC=1 bỏ A, B, C, F (giữ dữ liệu đã có); SKIP_ISOLATION=1 bỏ E (giữ isolation.json).
if [ "${SKIP_STATIC:-0}" != 1 ]; then
echo "── A. Chi phí mật mã phía máy khách"; OUT_DIR="$OUT" node_noble "$ROOT/scripts/eval/crypto.mjs" || exit 1
echo "── B. Băm không muối như máy xác nhận"; OUT_DIR="$OUT" node "$ROOT/scripts/eval/oracle.mjs" || exit 1
echo "── C. Danh sách bit trạng thái";       OUT_DIR="$OUT" node "$ROOT/scripts/eval/statuslist.mjs" || exit 1
if [ "${1:-}" != "--offline" ]; then
  echo "── F. Chuỗi thật (chỉ đọc + mô phỏng)"; PARTS=${CHAIN_PARTS:-rtt,gas} ROOT="$ROOT" OUT_DIR="$OUT" node_noble "$ROOT/scripts/eval/chain.mjs" || echo "  (F lỗi mạng — giữ dữ liệu cũ nếu có)"
fi
fi

# ---------------------------------------------------------------- D, E: cần hai backend
echo; echo "── Dựng môi trường cách ly"
start_db || exit 1
CPUSET_BEFORE=$(docker inspect -f '{{.HostConfig.CpusetCpus}}' "$PG_CONTAINER")
psql_c -d postgres -c "DROP DATABASE IF EXISTS $EVAL_DB WITH (FORCE)" -c "CREATE DATABASE $EVAL_DB" >/dev/null || exit 1
psql_c -d "$EVAL_DB" <"$ROOT/db/schema.sql" >/dev/null || exit 1
ok "CSDL $EVAL_DB đã nạp lược đồ"

ENV="DB_NAME=$EVAL_DB RATE_LIMIT_PER_MIN=10000000 AUTH_RATE_LIMIT_PER_MIN=100000 VERIFY_ONCHAIN=false LOG_LEVEL=warn"
(cd "$ROOT/backend-go" && go build -o ./bin/server ./cmd/server) || exit 1
up() { # up <cpus|->
  local pre=(); [ "$1" != - ] && pre=(taskset -c "$1")
  start_svc e-ts "$ROOT/backend" "${pre[@]}" env $ENV PORT=4020 npx tsx src/server.ts
  start_svc e-go "$ROOT/backend-go" "${pre[@]}" env $ENV PORT=4021 ./run.sh
  wait_up "$TS/health" "backend TS (:4020)" && wait_up "$GO/health" "backend Go (:4021)" 120
}
down() { stop_svc e-ts; stop_svc e-go; sleep 1; }
export TS_BASE=$TS GO_BASE=$GO OUT_DIR="$OUT" EVAL_DB DB_USER PG_CONTAINER

echo; echo "── E1. Không ghim CPU (bộ sinh tải chạy chung với hệ thống)"
up - || exit 1
node_pinned - "$ROOT/scripts/eval/load.mjs" setup || exit 1
[ "${SKIP_ISOLATION:-0}" = 1 ] || node_pinned - "$ROOT/scripts/eval/load.mjs" isolation shared || exit 1
down

echo; echo "── E2. Ghim CPU: dịch vụ + Postgres ở {$SVC_CPUS}, bộ sinh tải ở {$LOAD_CPUS}"
docker update --cpuset-cpus "$SVC_CPUS" "$PG_CONTAINER" >/dev/null || exit 1
up "$SVC_CPUS" || exit 1
[ "${SKIP_ISOLATION:-0}" = 1 ] || CPUSET_SVC=$SVC_CPUS CPUSET_LOAD=$LOAD_CPUS node_pinned "$LOAD_CPUS" "$ROOT/scripts/eval/load.mjs" isolation pinned || exit 1

echo; echo "── D. Quy mô dữ liệu (giữ cấu hình ghim CPU)"
node_pinned "$LOAD_CPUS" "$ROOT/scripts/eval/load.mjs" scale || exit 1
down

echo; echo "── Vẽ biểu đồ"
plot
