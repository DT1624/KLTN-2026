#!/usr/bin/env bash
# Publish gói Move lên Movement testnet rồi cập nhật CONTRACT_ADDRESS cho cả hệ thống.
#
#   ./scripts/deploy.sh                 # dùng profile mặc định "vnu-trust"
#   ./scripts/deploy.sh --profile tên   # dùng profile khác trong ~/.aptos/config.yaml
#   ./scripts/deploy.sh --init          # tạo profile mới trước khi publish
#
# VÌ SAO KHÔNG TỰ ĐỘNG CHẠY: publish là thao tác không lùi được và tạo ra hiện
# vật công khai. Ngoài ra `init_module` chỉ chạy MỘT LẦN cho mỗi địa chỉ, nên
# publish ở địa chỉ mới là cách duy nhất để đặt lại root_admin.
#
# AI THÀNH ROOT: Move.toml để root_admin = "_"; script truyền root_admin=0x0,
# khi đó `init_module` lấy CHÍNH NGƯỜI PUBLISH làm root (bản sửa F-00). Nghĩa là
# khoá riêng của profile bạn dùng ở đây chính là khoá root của toàn hệ thống.
# Khoá được lưu ở $KEY_DIR/.aptos/config.yaml (mặc định ~/.vnu-trust-deployer), quyền 600.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

PROFILE=vnu-trust
# Khoá riêng của profile nằm ở đây — NGOÀI mọi repo git. aptos đọc/ghi .aptos/ theo
# thư mục đang đứng, nên mọi lệnh aptos đều chạy từ KEY_DIR, không từ dự án.
KEY_DIR=${VNU_KEY_DIR:-$HOME/.vnu-trust-deployer}
DO_INIT=0
ASSUME_YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --profile) PROFILE=$2; shift 2 ;;
    --init)    DO_INIT=1; shift ;;
    -y|--yes)  ASSUME_YES=1; shift ;;
    *) echo "Tham số lạ: $1"; exit 1 ;;
  esac
done

command -v aptos >/dev/null || { echo "Không tìm thấy lệnh 'aptos'. Cài Aptos CLI trước."; exit 1; }

mkdir -p "$KEY_DIR" && chmod 700 "$KEY_DIR"
if git -C "$KEY_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "KEY_DIR=$KEY_DIR nằm trong một repo git — từ chối để khoá riêng không bị commit."; exit 1
fi
cd "$KEY_DIR"

# shellcheck disable=SC1091
set -a; . "$ROOT/chain.env"; set +a

if [ "$DO_INIT" = 1 ]; then
  echo "Tạo profile '$PROFILE' trỏ vào $CHAIN_FULLNODE…"
  # Lọc mọi dòng nhắc tới khoá riêng khỏi đầu ra cho chắc.
  rc=0; aptos init --profile "$PROFILE" --network custom \
    --rest-url "$CHAIN_FULLNODE" --faucet-url "$CHAIN_FAUCET" --assume-yes >init.log 2>&1 || rc=$?
  grep -vi "private" init.log || true; rm -f init.log
  [ "$rc" = 0 ] || exit "$rc"
  chmod 600 "$KEY_DIR/.aptos/config.yaml"
fi

ADDR=$(aptos config show-profiles --profile "$PROFILE" 2>/dev/null \
  | grep -oE '"account": "[0-9a-fx]+"' | grep -oE '[0-9a-fx]+$' | head -1)
[ -n "$ADDR" ] || { echo "Không đọc được địa chỉ của profile '$PROFILE'. Chạy lại với --init."; exit 1; }
case "$ADDR" in 0x*) ;; *) ADDR="0x$ADDR" ;; esac

BAL=$(curl -s "$CHAIN_FULLNODE/accounts/$ADDR/balance/0x1::aptos_coin::AptosCoin" 2>/dev/null || echo 0)
echo
echo "  Địa chỉ publish : $ADDR"
echo "  Số dư           : ${BAL:-0} octas"
echo "  Fullnode        : $CHAIN_FULLNODE (chain id $CHAIN_ID)"
echo
echo "  Sau khi publish, $ADDR sẽ là ROOT_ADMIN của hệ thống."
echo "  Địa chỉ hợp đồng cũ ($CONTRACT_ADDRESS) sẽ KHÔNG còn được dùng;"
echo "  toàn bộ DID và văn bằng đã neo ở đó bị bỏ lại."
echo
if [ "$ASSUME_YES" != 1 ]; then
  read -r -p "Tiếp tục publish? [nhập 'publish' để xác nhận] " ans
  [ "$ans" = "publish" ] || { echo "Đã huỷ."; exit 1; }
fi

# Nạp gas nếu tài khoản còn quá ít. Publish tốn nhiều hơn một giao dịch thường.
if [ "${BAL:-0}" -lt 50000000 ] 2>/dev/null; then
  echo "Số dư thấp — xin faucet…"
  curl -s -X POST "$CHAIN_FAUCET/mint?amount=200000000&address=$ADDR" >/dev/null || true
  sleep 3
fi

echo "Đang publish…"
( aptos move publish \
    --package-dir "$ROOT/contracts" \
    --profile "$PROFILE" \
    --named-addresses "vnu=$ADDR,root_admin=0x0" \
    --skip-fetch-latest-git-deps \
    --assume-yes )

echo
echo "Cập nhật chain.env → CONTRACT_ADDRESS=$ADDR"
sed -i -E "s|^CONTRACT_ADDRESS=.*$|CONTRACT_ADDRESS=$ADDR|" "$ROOT/chain.env"
"$ROOT/scripts/sync-chain-env.sh"

cat <<EOF

XONG. Việc còn lại:
  1. Đặt VERIFY_ONCHAIN=true trong backend/.env và backend-go/.env
  2. make restart                                     (nạp lại biến môi trường)
  3. Mở giao diện bằng ví của $ADDR — ví đó là root, vào mục "Quản trị gốc"
  4. make test                                        (chạy lại toàn bộ bộ kiểm thử)

Kiểm tra nhanh ABI đã lên đúng bản mới:
  curl -s $CHAIN_FULLNODE/accounts/$ADDR/module/vc_registry | grep -o '"name":"issue_vc".\{0,400\}' | head -1
EOF
