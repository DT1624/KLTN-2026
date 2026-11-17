#!/usr/bin/env bash
# Đo hiệu năng CHỈ backend TS (cho khoá luận): setup -> sweep -> scale.
#   ./scripts/eval-ts.sh            ghi vào .bench/eval-ts (hoặc $OUT)
# Cách ly như eval.sh: CSDL vnu_trust_eval, cổng 4020, Postgres + backend ghim CPU {0,1},
# bộ sinh tải ghim {2,3}. Xong tự dọn, trả cpuset, xoá state.json.
. "$(dirname "$0")/lib.sh"

EVAL_DB=vnu_trust_eval
OUT="${OUT:-$ROOT/.bench/eval-ts}"
TS=http://localhost:4020/api
NCPU=$(nproc)
SVC_CPUS=0,1
LOAD_CPUS=2,3
mkdir -p "$OUT"

node_pinned() { # node_pinned <cpus|-> <tệp> [đối số…]
  local cpus=$1 src=$2 tmp="$ROOT/frontend/.tmp-$(basename "$2")" rc; shift 2
  cp "$src" "$tmp" || return 1
  if [ "$cpus" = - ]; then (cd "$ROOT/frontend" && node "$tmp" "$@"); else (cd "$ROOT/frontend" && taskset -c "$cpus" node "$tmp" "$@"); fi
  rc=$?; rm -f "$tmp"; return $rc
}

HAD_VOLUME=$(docker volume ls -q --filter name=vnu_trust_pgdata | grep -c . || true)
HAD_CONTAINER=$(docker ps -aq --filter name=$PG_CONTAINER | grep -c . || true)
DB_WAS_UP=0; docker exec "$PG_CONTAINER" pg_isready -U "$DB_USER" >/dev/null 2>&1 && DB_WAS_UP=1
CPUSET_BEFORE=""
cleanup() {
  echo; echo "── Dọn dẹp"
  stop_svc e-ts 2>/dev/null
  stop_port 4020 2>/dev/null
  if docker ps -q --filter name=$PG_CONTAINER | grep -q .; then
    docker update --cpuset-cpus "${CPUSET_BEFORE:-0-$((NCPU - 1))}" "$PG_CONTAINER" >/dev/null 2>&1 && ok "trả lại cpuset của Postgres"
    psql_c -d postgres -c "DROP DATABASE IF EXISTS $EVAL_DB WITH (FORCE)" >/dev/null 2>&1 && ok "đã xoá CSDL $EVAL_DB"
  fi
  if [ "$HAD_VOLUME" = 0 ] && [ "$HAD_CONTAINER" = 0 ]; then
    (cd "$ROOT" && docker compose down -v >/dev/null 2>&1) && ok "trước đó chưa có Postgres: đã xoá container, network, volume"
  elif [ "$DB_WAS_UP" = 0 ]; then
    (cd "$ROOT" && docker compose stop >/dev/null 2>&1) && ok "đã tắt lại Postgres"
  fi
  rm -f "$OUT/state.json" "$RUN"/e-*.log "$ROOT"/frontend/.tmp-*.mjs
  ok "đã xoá tệp trạng thái, log"
}
trap cleanup EXIT

echo "── Dựng môi trường cách ly"
start_db || exit 1
CPUSET_BEFORE=$(docker inspect -f '{{.HostConfig.CpusetCpus}}' "$PG_CONTAINER")
psql_c -d postgres -c "DROP DATABASE IF EXISTS $EVAL_DB WITH (FORCE)" -c "CREATE DATABASE $EVAL_DB" >/dev/null || exit 1
psql_c -d "$EVAL_DB" <"$ROOT/db/schema.sql" >/dev/null || exit 1
ok "CSDL $EVAL_DB đã nạp lược đồ"

ENV="DB_NAME=$EVAL_DB RATE_LIMIT_PER_MIN=10000000 AUTH_RATE_LIMIT_PER_MIN=100000 VERIFY_ONCHAIN=false LOG_LEVEL=warn"
export TS_BASE=$TS OUT_DIR="$OUT" EVAL_DB DB_USER PG_CONTAINER BACKENDS=TS
export CPUSET_SVC=$SVC_CPUS CPUSET_LOAD=$LOAD_CPUS

echo "── Ghim CPU: Postgres + backend TS ở {$SVC_CPUS}, bộ sinh tải ở {$LOAD_CPUS}"
docker update --cpuset-cpus "$SVC_CPUS" "$PG_CONTAINER" >/dev/null || exit 1
start_svc e-ts "$ROOT/backend" taskset -c "$SVC_CPUS" env $ENV PORT=4020 npx tsx src/server.ts
wait_up "$TS/health" "backend TS (:4020)" || exit 1

# PHASES: danh sách pha, mặc định "setup,sweep,scale" (hành vi cũ). `PHASES=tamper` chỉ chạy
# ma trận phát hiện giả mạo (M1), tự dựng actor riêng nên không cần pha setup.
PHASES="${PHASES:-setup,sweep,scale}"
has_phase() { case ",$PHASES," in *",$1,"*) return 0;; *) return 1;; esac; }
for ph in setup sweep scale; do
  has_phase "$ph" && { echo "── $ph"; node_pinned "$LOAD_CPUS" "$ROOT/scripts/eval/load.mjs" "$ph" || exit 1; }
done
has_phase tamper && { echo "── tamper"; node_pinned "$LOAD_CPUS" "$ROOT/scripts/eval/tamper-matrix.mjs" || exit 1; }
stop_svc e-ts
