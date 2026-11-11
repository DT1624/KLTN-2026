#!/usr/bin/env bash
# Bật / tắt từng thành phần hoặc cả hệ thống.
#
#   ./scripts/dev.sh up   [all|db|ts|go|ui]   bật (mặc định: all)
#   ./scripts/dev.sh down [all|db|ts|go|ui]   tắt (mặc định: all, giữ volume dữ liệu)
#   ./scripts/dev.sh restart [thành phần]
#   ./scripts/dev.sh status
#   ./scripts/dev.sh logs <ts|go|ui>
#
# Chỉ cần MỘT backend: giao diện chọn TS/Go ở thanh trên, bên nào không chạy thì
# báo đỏ ở bộ chọn. Ví dụ chỉ chạy bản Go: dev.sh up db && dev.sh up go && dev.sh up ui
. "$(dirname "$0")/lib.sh"

up() {
  case $1 in
    db) start_db ;;
    ts) is_up http://localhost:4000/api/health && { info "backend TS đã chạy"; return; }
        start_svc ts "$ROOT/backend" npm run dev
        wait_up http://localhost:4000/api/health "backend TS (:4000)" ;;
    go) is_up http://localhost:4001/api/health && { info "backend Go đã chạy"; return; }
        start_svc go "$ROOT/backend-go" ./run.sh
        wait_up http://localhost:4001/api/health "backend Go (:4001)" 120 ;;
    ui) is_up http://localhost:5173/ && { info "frontend đã chạy"; return; }
        start_svc ui "$ROOT/frontend" npm run dev
        wait_up http://localhost:5173/ "frontend   (:5173)" ;;
    all) up db && up ts && up go && up ui || return 1
         echo; echo "  Giao diện   http://localhost:5173"
         echo "  Backend TS  http://localhost:4000/api"
         echo "  Backend Go  http://localhost:4001/api" ;;
    *) err "thành phần lạ: $1"; return 1 ;;
  esac
}

down() {
  case $1 in
    db) (cd "$ROOT" && docker compose stop >/dev/null 2>&1) && ok "đã dừng Postgres (dữ liệu giữ trong volume)" ;;
    ts|go|ui)
      local port; case $1 in ts) port=4000 ;; go) port=4001 ;; ui) port=5173 ;; esac
      if stop_svc "$1" || stop_port "$port"; then ok "đã dừng $1 (:$port)"; else info "$1 không chạy"; fi ;;
    all) down ui; down ts; down go; down db ;;
    *) err "thành phần lạ: $1"; return 1 ;;
  esac
}

case "${1:-}" in
  up)      up "${2:-all}" ;;
  down)    down "${2:-all}" ;;
  restart) down "${2:-all}"; sleep 1; up "${2:-all}" ;;
  status)
    for p in "5173 frontend" "4000 backend TS" "4001 backend Go"; do
      set -- $p; pid=$(port_pid "$1")
      [ -n "$pid" ] && echo "  ● :$1  ${*:2}  (pid $pid)" || echo "  ○ :$1  ${*:2}"
    done
    docker ps --filter name=$PG_CONTAINER --format '  ● {{.Names}}  {{.Status}}' 2>/dev/null | grep . || echo "  ○ Postgres" ;;
  logs)    tail -n 80 -f "$RUN/${2:?chọn ts|go|ui}.log" ;;
  *)       sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
