# Hàm dùng chung cho các script vận hành. Nạp bằng: . "$(dirname "$0")/lib.sh"
set -uo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUN="$ROOT/.run"            # pid và log của các dịch vụ do script bật
mkdir -p "$RUN"
export GOFLAGS=${GOFLAGS:--mod=mod}

PG_CONTAINER=vnu_trust_postgres
DB_USER=$(grep -E '^DB_USER=' "$ROOT/.env" 2>/dev/null | cut -d= -f2); DB_USER=${DB_USER:-vnu_trust}

ok()   { echo "  ✓ $*"; }
info() { echo "  · $*"; }
err()  { echo "  ✗ $*" >&2; }

port_pid() { ss -ltnp 2>/dev/null | grep ":$1 " | grep -oP 'pid=\K[0-9]+' | head -1; }
is_up()    { [ "$(curl -s -o /dev/null -w '%{http_code}' "$1" 2>/dev/null)" = "200" ]; }

wait_up() { # wait_up <url> <tên> [giây]
  local i
  for ((i = 0; i < ${3:-60}; i++)); do
    is_up "$1" && { ok "$2 sẵn sàng"; return 0; }
    sleep 1
  done
  err "$2 không lên sau ${3:-60}s — xem $RUN/"; return 1
}

# start_svc <tên> <thư mục> <lệnh...> — chạy trong nhóm tiến trình riêng (setsid)
# để lúc dừng giết được cả cây (npm → tsx watch → node), không sót tiến trình con.
# setsid có thể tự fork nên $! không đáng tin: để chính tiến trình con ghi PID của nó.
start_svc() {
  local name=$1 dir=$2; shift 2
  # exec: không để lại subshell trung gian giữ stdout của người gọi (làm `| tail` treo).
  (cd "$dir" && exec setsid bash -c 'echo $$ >"$0"; exec "$@"' "$RUN/$name.pid" "$@") \
    >"$RUN/$name.log" 2>&1 </dev/null &
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$RUN/$name.pid" ] && return 0; sleep 0.2; done
}

stop_svc() { # stop_svc <tên> — giết cả nhóm tiến trình đã ghi trong .pid
  local f="$RUN/$1.pid" pid
  [ -f "$f" ] || return 1
  pid=$(cat "$f"); rm -f "$f"
  kill -0 "$pid" 2>/dev/null || return 1
  kill -- -"$pid" 2>/dev/null || kill "$pid" 2>/dev/null
  for _ in 1 2 3 4 5; do kill -0 "$pid" 2>/dev/null || return 0; sleep 1; done
  kill -9 -- -"$pid" 2>/dev/null; return 0
}

stop_port() { # dự phòng cho tiến trình không bật qua start_svc
  local pid; pid=$(port_pid "$1")
  [ -n "$pid" ] && kill "$pid" 2>/dev/null && return 0
  return 1
}

start_db() {
  if ! docker exec "$PG_CONTAINER" pg_isready -U "$DB_USER" >/dev/null 2>&1; then
    (cd "$ROOT" && docker compose up -d >/dev/null 2>&1) || { err "không bật được Postgres (Docker đang chạy chưa?)"; return 1; }
  fi
  for _ in $(seq 1 30); do
    docker exec "$PG_CONTAINER" pg_isready -U "$DB_USER" >/dev/null 2>&1 && { ok "Postgres sẵn sàng"; return 0; }
    sleep 1
  done
  err "Postgres không sẵn sàng"; return 1
}

psql_c() { docker exec -i "$PG_CONTAINER" psql -q -v ON_ERROR_STOP=1 -U "$DB_USER" "$@"; }

# Các tập lệnh dùng @noble/* chỉ có trong node_modules của frontend: chép tạm vào
# đó để Node tìm thấy gói, chạy xong xoá.
node_noble() { # node_noble <tệp .mjs> [đối số...]
  local src=$1 tmp="$ROOT/frontend/.tmp-$(basename "$1")" rc; shift
  cp "$src" "$tmp" && (cd "$ROOT/frontend" && node "$tmp" "$@"); rc=$?
  rm -f "$tmp"; return $rc
}
