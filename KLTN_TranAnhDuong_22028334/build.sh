#!/usr/bin/env bash
#
# Biên dịch khoá luận thành PDF hoàn chỉnh, ngay trên máy.
#
# Overleaf bản miễn phí dừng biên dịch sau một hạn thời gian cố định, mà tài
# liệu này có 178 trang, 8 hình và 4 biểu đồ pgfplots sinh từ dữ liệu đo nhúng
# thẳng vào tệp .tex — nên nó chạm trần. Chạy cục bộ thì không có hạn đó.
#
#   ./build.sh          biên dịch -> out/main.pdf
#   ./build.sh clean    xoá toàn bộ tệp trung gian trong out/
#
# Công cụ: Tectonic (https://tectonic-typesetting.github.io) — một tệp nhị phân
# duy nhất, tự tải đúng gói LaTeX nó cần về bộ đệm của người dùng, không cần
# quyền root và không cần cài cả bộ TeX Live 5GB.

set -euo pipefail
cd "$(dirname "$0")"

TECTONIC="${TECTONIC:-$HOME/.local/bin/tectonic}"
OUT="${OUT:-out}"

if [ ! -x "$TECTONIC" ]; then
  echo "Không thấy tectonic ở $TECTONIC" >&2
  echo "Cài lại:" >&2
  echo "  curl -fsSL https://github.com/tectonic-typesetting/tectonic/releases/download/tectonic%400.17.0/tectonic-0.17.0-x86_64-unknown-linux-gnu.tar.gz | tar xz -C /tmp" >&2
  echo "  install -m755 /tmp/tectonic ~/.local/bin/tectonic" >&2
  exit 1
fi

if [ "${1:-}" = "clean" ]; then
  rm -rf "$OUT"
  echo "Đã xoá $OUT/"
  exit 0
fi

# Phông Times New Roman: fontspec tìm qua fontconfig. Trên WSL có thể lấy thẳng
# từ Windows mà không cần cài gói phông nào.
if ! fc-match "Times New Roman" 2>/dev/null | grep -qi times; then
  if ls /mnt/c/Windows/Fonts/times*.ttf >/dev/null 2>&1; then
    echo "Chép Times New Roman từ Windows sang ~/.local/share/fonts …"
    mkdir -p "$HOME/.local/share/fonts/msttf"
    cp /mnt/c/Windows/Fonts/times*.ttf "$HOME/.local/share/fonts/msttf/"
    fc-cache -f "$HOME/.local/share/fonts" >/dev/null
  else
    echo "CẢNH BÁO: không tìm thấy phông Times New Roman, fontspec sẽ báo lỗi." >&2
  fi
fi

mkdir -p "$OUT"
t0=$(date +%s)
"$TECTONIC" -X compile main.tex \
  --outdir "$OUT" \
  --keep-intermediates \
  --keep-logs \
  --synctex \
  "$@"
t1=$(date +%s)

pages=$(grep -oE '\([0-9]+ pages' "$OUT/main.log" | tail -1 | tr -dc '0-9')
echo
echo "Xong sau $((t1 - t0))s -> $OUT/main.pdf (${pages:-?} trang)"

# Những cảnh báo đáng xem lại; không làm hỏng bản dựng nhưng nên biết.
bad=$(grep -c 'Overfull \\hbox' "$OUT/main.log" || true)
miss=$(grep -c 'Missing character' "$OUT/main.log" || true)
ref=$(grep -cE "LaTeX Warning: (Reference|Citation) " "$OUT/main.log" || true)
echo "   tràn lề: $bad   thiếu ký tự: $miss   tham chiếu/trích dẫn hỏng: $ref"
