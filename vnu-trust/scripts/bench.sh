#!/usr/bin/env bash
# Đo hiệu năng trên hai backend dev (cổng 4000/4001) với hạn mức nâng cao, rồi trả về như cũ.
#
#   ./scripts/bench.sh            đo nhanh (perf.mjs)
#   ./scripts/bench.sh --report   bộ đo mở rộng cho báo cáo: .bench/*.json → .bench/tex/*.tex
#
# Không phải kiểm thử: dữ liệu đo nằm trong CSDL dev và .bench/ (giữ lại cho báo cáo).
. "$(dirname "$0")/lib.sh"

start_db || exit 1
was_ts=$(port_pid 4000); was_go=$(port_pid 4001)
stop_svc ts || stop_port 4000; stop_svc go || stop_port 4001; sleep 1

ENV="RATE_LIMIT_PER_MIN=1000000 AUTH_RATE_LIMIT_PER_MIN=50000 LOG_LEVEL=warn"
start_svc b-ts "$ROOT/backend" env $ENV npx tsx src/server.ts
start_svc b-go "$ROOT/backend-go" env $ENV ./run.sh
wait_up http://localhost:4000/api/health "backend TS" && wait_up http://localhost:4001/api/health "backend Go" 120 || exit 1

rc=0
if [ "${1:-}" = "--report" ]; then
  for s in sweep samplesize sweep2; do OUT_DIR="$ROOT/.bench" node_noble "$ROOT/scripts/bench/$s.mjs" || rc=1; done
  (cd "$ROOT" && node scripts/bench/plot.mjs) || rc=1
else
  node_noble "$ROOT/scripts/perf.mjs" || rc=1
fi

stop_svc b-ts; stop_svc b-go; rm -f "$RUN"/b-*.log
# Trả lại đúng trạng thái trước khi đo.
[ -n "$was_ts" ] && "$ROOT/scripts/dev.sh" up ts
[ -n "$was_go" ] && "$ROOT/scripts/dev.sh" up go
exit $rc
