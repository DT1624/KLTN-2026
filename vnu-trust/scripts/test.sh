#!/usr/bin/env bash
# Chạy toàn bộ bộ kiểm thử trong môi trường CÁCH LY rồi dọn sạch.
#
#   ./scripts/test.sh            tất cả
#   ./scripts/test.sh --quick    chỉ phần tĩnh (Move, ABI, typecheck, go test) — không cần CSDL
#
# Cách ly: CSDL riêng `vnu_trust_test` (tạo mới mỗi lượt, xoá khi xong) và cổng
# riêng 4010/4011 (nghiêm ngặt: 4097/4098; nghiêm ngặt với fullnode giả: 4095/4096 + 4099). Bản dev đang chạy và dữ liệu dev không
# bị đụng tới; Postgres chỉ bị tắt lại nếu trước đó nó chưa chạy.
. "$(dirname "$0")/lib.sh"

TEST_DB=vnu_trust_test
TS=http://localhost:4010/api
GO=http://localhost:4011/api
fail=0
run() { local name=$1; shift; echo; echo "── $name"; bash -o pipefail -c "$*" || { fail=1; FAILED+=("$name"); }; }
FAILED=()

static_checks() {
  run "Hợp đồng Move"           "cd '$ROOT/contracts' && aptos move test --skip-fetch-latest-git-deps 2>&1 | tail -3"
  run "Tên hàm contract ↔ code" "cd '$ROOT' && node scripts/abi-check.mjs | tail -2"
  run "Go: gofmt + vet + test"  "cd '$ROOT/backend-go' && test -z \"\$(gofmt -l .)\" && go vet ./... && go test ./... 2>&1 | grep -v 'no test files'"
  run "TS: typecheck"           "cd '$ROOT/backend' && npx tsc --noEmit"
  run "Frontend: typecheck"     "cd '$ROOT/frontend' && npx tsc --noEmit"
  run "Ví: bảng kiểu BCS ↔ Move" "cd '$ROOT/frontend' && ../backend/node_modules/.bin/tsx scripts/bcs-check.ts | tail -1"
  run "Ví: khôi phục từ cụm từ"  "cd '$ROOT/frontend' && ../backend/node_modules/.bin/tsx scripts/wallet-restore.ts | tail -1"
  run "Mã hoá văn bằng (P3)"     "cd '$ROOT/frontend' && ../backend/node_modules/.bin/tsx scripts/vc-crypto-check.ts | tail -1"
  run "Nhắc sao lưu (P4.3)"      "cd '$ROOT/frontend' && ../backend/node_modules/.bin/tsx scripts/backup-check.ts | tail -1"
}

cleanup() {
  for s in t-ts t-go t-ts-strict t-go-strict t-ts-mock t-go-mock; do stop_svc "$s" 2>/dev/null; done
  if docker exec "$PG_CONTAINER" pg_isready -U "$DB_USER" >/dev/null 2>&1; then
    psql_c -d postgres -c "DROP DATABASE IF EXISTS $TEST_DB WITH (FORCE)" >/dev/null 2>&1 && ok "đã xoá CSDL $TEST_DB"
    [ "${DB_WAS_UP:-1}" = 0 ] && (cd "$ROOT" && docker compose stop >/dev/null 2>&1) && ok "đã tắt lại Postgres"
  fi
  rm -f "$RUN"/t-*.log "$ROOT"/frontend/.tmp-*.mjs
}

static_checks
if [ "${1:-}" = "--quick" ]; then
  echo; [ $fail = 0 ] && echo "TẤT CẢ ĐẠT" || echo "THẤT BẠI: ${FAILED[*]}"; exit $fail
fi

echo; echo "── Dựng môi trường kiểm thử cách ly"
docker exec "$PG_CONTAINER" pg_isready -U "$DB_USER" >/dev/null 2>&1 && DB_WAS_UP=1 || DB_WAS_UP=0
trap cleanup EXIT
start_db || exit 1
psql_c -d postgres -c "DROP DATABASE IF EXISTS $TEST_DB WITH (FORCE)" -c "CREATE DATABASE $TEST_DB" >/dev/null || exit 1
psql_c -d "$TEST_DB" <"$ROOT/db/schema.sql" >/dev/null || exit 1
ok "CSDL $TEST_DB đã nạp lược đồ"

# Hạn mức nâng cao: không bộ nào khẳng định hành vi 429, để mặc định thì dính 429 ngẫu nhiên.
ENV="DB_NAME=$TEST_DB RATE_LIMIT_PER_MIN=100000 AUTH_RATE_LIMIT_PER_MIN=5000 VERIFY_ONCHAIN=false LOG_LEVEL=warn"
start_svc t-ts "$ROOT/backend" env $ENV PORT=4010 npx tsx src/server.ts
start_svc t-go "$ROOT/backend-go" env $ENV PORT=4011 ./run.sh
wait_up "$TS/health" "backend TS (:4010)" || exit 1
wait_up "$GO/health" "backend Go (:4011)" 120 || exit 1

export DB_NAME=$TEST_DB
for side in "TS $TS" "Go $GO"; do
  set -- $side
  run "Luồng nghiệp vụ — $1"      "cd '$ROOT/backend' && API_BASE=$2 node scripts/full-flow.mjs | tail -2"
  run "E2E — $1"                  "cd '$ROOT/backend' && API_BASE=$2 node scripts/e2e.mjs | tail -2"
  run "Phát hiện sửa nội dung — $1" "cd '$ROOT/backend' && API_BASE=$2 node scripts/tamper-check.mjs | tail -2"
  run "Hồi quy bảo mật — $1"     "cd '$ROOT/backend' && API_BASE=$2 node scripts/security-regression.mjs | tail -2"
done
run "Ví trong trình duyệt"  "cd '$ROOT/frontend' && API_BASE=$TS node scripts/wallet-e2e.mjs | tail -2"
run "Đăng nhập máy khác"    "cd '$ROOT/frontend' && API_BASE=$TS node scripts/cross-device.mjs | tail -2"
run "Đối chiếu hai backend" ". '$ROOT/scripts/lib.sh' && TS_BASE=$TS GO_BASE=$GO node_noble '$ROOT/scripts/parity.mjs' | tail -2"

# Chế độ nghiêm ngặt cần fullnode thật (mạng) để hỏi quyền trên chuỗi.
STRICT="DB_NAME=$TEST_DB VERIFY_ONCHAIN=true LOG_LEVEL=warn"
start_svc t-ts-strict "$ROOT/backend" env $STRICT PORT=4097 npx tsx src/server.ts
start_svc t-go-strict "$ROOT/backend-go" env $STRICT PORT=4098 ./run.sh
for side in "TS 4097 60" "Go 4098 120"; do
  set -- $side
  if wait_up "http://localhost:$2/health" "$1 nghiêm ngặt (:$2)" "$3"; then
    run "Chế độ nghiêm ngặt — $1" "cd '$ROOT/backend' && API_BASE=http://localhost:$2/api node scripts/strict-mode.mjs | tail -2"
  else fail=1; FAILED+=("Chế độ nghiêm ngặt — $1"); fi
done

# Xác minh giao dịch ở chế độ nghiêm ngặt, với fullnode GIẢ (tx-binding.mjs tự bật
# ở :4099): chứng minh backend đối chiếu đủ tham số mà không phải ghi gì lên chuỗi.
MOCK="DB_NAME=$TEST_DB VERIFY_ONCHAIN=true CHAIN_FULLNODE=http://localhost:4099/v1 LOG_LEVEL=warn RATE_LIMIT_PER_MIN=100000 AUTH_RATE_LIMIT_PER_MIN=5000"
start_svc t-ts-mock "$ROOT/backend" env $MOCK PORT=4095 npx tsx src/server.ts
start_svc t-go-mock "$ROOT/backend-go" env $MOCK PORT=4096 ./run.sh
if wait_up "http://localhost:4095/health" "TS nghiêm ngặt-giả (:4095)" 60 && wait_up "http://localhost:4096/health" "Go nghiêm ngặt-giả (:4096)" 120; then
  run "Xác minh giao dịch đủ tham số" "cd '$ROOT/backend' && TS_BASE=http://localhost:4095/api GO_BASE=http://localhost:4096/api node scripts/tx-binding.mjs | tail -2"
else fail=1; FAILED+=("Xác minh giao dịch đủ tham số"); fi

echo; echo "── Dọn dẹp"
cleanup; trap - EXIT
echo; [ $fail = 0 ] && echo "TẤT CẢ ĐẠT" || echo "THẤT BẠI: ${FAILED[*]}"
exit $fail
