#!/usr/bin/env bash
# Kiểm tra nhanh bản triển khai từ máy bạn:
#   1. render.yaml dùng đúng địa chỉ hợp đồng trong chain.env
#   2. hai backend sống, đang kiểm chứng trên chuỗi
#   3. CORS cho phép đúng domain của frontend
#   4. frontend trả trang, kể cả đường dẫn con (rewrite của SPA)
#
# Lần gọi đầu có thể mất tới ~60 giây vì gói free của Render cho backend ngủ.
set -uo pipefail
cd "$(dirname "$0")"
# Nạp deploy/.env nhưng biến đặt sẵn từ dòng lệnh được ưu tiên,
# vd. WEB_URL=https://x.vercel.app ./check.sh
if [ -f .env ]; then
  while IFS='=' read -r k v; do
    [[ $k =~ ^[A-Z_][A-Z0-9_]*$ ]] && [ -z "${!k+x}" ] && export "$k=$v"
  done < .env
fi
: "${WEB_URL:?thiếu WEB_URL trong deploy/.env}" "${TS_URL:?thiếu TS_URL}" "${GO_URL:?thiếu GO_URL}"

pass=0 fail=0
ok()  { echo "  ĐẠT  $1"; pass=$((pass+1)); }
bad() { echo "  HỎNG $1"; fail=$((fail+1)); }

echo "1. Địa chỉ hợp đồng"
want=$(grep -E '^CONTRACT_ADDRESS=' ../chain.env | cut -d= -f2)
n=$(grep -c "$want" render.yaml)
[ "$n" -eq 2 ] && ok "render.yaml khớp chain.env ($want)" \
               || bad "render.yaml có $n/2 chỗ khớp chain.env — sửa CONTRACT_ADDRESS và VITE_CONTRACT_ADDRESS"

echo "2. Backend (có thể chờ backend thức dậy)"
for pair in "TypeScript|$TS_URL" "Go|$GO_URL"; do
  name=${pair%%|*} url=${pair#*|}
  body=$(curl -fsS --max-time 90 "$url/health" 2>/dev/null) || { bad "$name: $url/health không trả lời"; continue; }
  echo "$body" | grep -q '"verifyOnChain":true' \
    && ok "$name sống, verifyOnChain=true" \
    || bad "$name sống nhưng verifyOnChain không phải true: $body"
done

echo "3. CORS"
for pair in "TypeScript|$TS_URL" "Go|$GO_URL"; do
  name=${pair%%|*} url=${pair#*|}
  allow=$(curl -sS --max-time 30 -o /dev/null -D - -H "Origin: $WEB_URL" "$url/api/health" \
          | tr -d '\r' | grep -i '^access-control-allow-origin:' | cut -d' ' -f2)
  [ "$allow" = "$WEB_URL" ] && ok "$name cho phép $WEB_URL" \
                            || bad "$name không cho phép $WEB_URL — kiểm tra FRONTEND_ORIGIN"
done

echo "4. Frontend"
for path in / /verify; do
  code=$(curl -s --max-time 30 -o /dev/null -w '%{http_code}' "$WEB_URL$path")
  [ "$code" = 200 ] && ok "$WEB_URL$path → 200" || bad "$WEB_URL$path → $code"
done

echo
echo "Kết quả: $pass đạt, $fail hỏng"
[ "$fail" -eq 0 ]
