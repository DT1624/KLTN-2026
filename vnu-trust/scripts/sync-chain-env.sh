#!/usr/bin/env bash
# Đẩy thông số trong chain.env sang ba tệp .env của backend TS, backend Go và
# frontend. Chỉ ghi đè đúng những khoá liên quan tới chuỗi, giữ nguyên phần còn
# lại (backend/.env còn chứa JWT_SECRET và PINATA_JWT).
#
# Frontend nhận cùng các giá trị đó dưới tiền tố VITE_ vì Vite chỉ lộ biến có
# tiền tố này ra mã trình duyệt.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

[ -f chain.env ] || { echo "Thiếu chain.env ở $ROOT"; exit 1; }
# shellcheck disable=SC1091
set -a; . ./chain.env; set +a

: "${CONTRACT_ADDRESS:?chain.env thiếu CONTRACT_ADDRESS}"
: "${CHAIN_FULLNODE:?chain.env thiếu CHAIN_FULLNODE}"
: "${CHAIN_ID:?chain.env thiếu CHAIN_ID}"
: "${CHAIN_FAUCET:?chain.env thiếu CHAIN_FAUCET}"
: "${CHAIN_EXPLORER:=https://explorer.movementnetwork.xyz/txn}"

# put <tệp> <khoá> <giá trị> — có thì sửa tại chỗ, chưa có thì thêm vào cuối.
put() {
  local file=$1 key=$2 val=$3
  touch "$file"
  if grep -qE "^${key}=" "$file"; then
    # Dùng | làm dấu phân cách vì giá trị có chứa dấu /
    sed -i -E "s|^${key}=.*$|${key}=${val}|" "$file"
  else
    printf '%s=%s\n' "$key" "$val" >>"$file"
  fi
}

for f in backend/.env backend/.env.example backend-go/.env backend-go/.env.example; do
  [ -f "$f" ] || continue
  put "$f" CONTRACT_ADDRESS "$CONTRACT_ADDRESS"
  put "$f" CHAIN_FULLNODE   "$CHAIN_FULLNODE"
  put "$f" CHAIN_ID         "$CHAIN_ID"
  echo "  ✓ $f"
done

for f in frontend/.env frontend/.env.example; do
  [ -f "$f" ] || continue
  put "$f" VITE_CONTRACT_ADDRESS "$CONTRACT_ADDRESS"
  put "$f" VITE_CHAIN_FULLNODE   "$CHAIN_FULLNODE"
  put "$f" VITE_CHAIN_ID         "$CHAIN_ID"
  put "$f" VITE_CHAIN_FAUCET     "$CHAIN_FAUCET"
  put "$f" VITE_CHAIN_EXPLORER   "$CHAIN_EXPLORER"
  echo "  ✓ $f"
done

echo
echo "CONTRACT_ADDRESS = $CONTRACT_ADDRESS"
echo "Frontend đang chạy thì phải khởi động lại Vite — biến VITE_* đọc lúc khởi động."
