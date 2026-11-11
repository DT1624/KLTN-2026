import { explorerTxUrl } from "../lib/chain";
import type { ChainTx } from "../hooks/useChain";
import { Alert, Mono } from "./ui";

/**
 * Hiển thị tiến trình một lượt ký & gửi giao dịch.
 *
 * Thay cho ô "dán mã giao dịch" ngày trước: người dùng bấm nút, ví ký, giao
 * dịch lên chuỗi, và mã giao dịch **hiện ra** như kết quả chứ không phải là
 * thứ họ phải tự đi tìm rồi nhập vào.
 */
export default function TxProgress({ tx, okTitle = "Xong" }: { tx: ChainTx; okTitle?: string }) {
  if (tx.step === "idle") return null;

  if (tx.busy) {
    return (
      <div className="flex items-center gap-3 rounded-xl border border-brand-200 bg-brand-50 px-4 py-3 text-sm text-brand-900">
        <span className="w-4 h-4 rounded-full border-2 border-brand-200 border-t-brand-600 animate-spin" />
        {tx.label}
      </div>
    );
  }

  if (tx.step === "error") {
    return <Alert tone="bad" title="Không thực hiện được">{tx.error}</Alert>;
  }

  return (
    <Alert tone={tx.submitted ? "ok" : "warn"} title={okTitle}>
      {tx.hash && (
        <div className="mt-1 flex flex-wrap items-center gap-2">
          <span>{tx.submitted ? "Mã giao dịch:" : "Tham chiếu cục bộ:"}</span>
          <Mono value={tx.hash} />
          {tx.submitted && (
            <a className="underline hover:no-underline" target="_blank" rel="noreferrer"
              href={explorerTxUrl(tx.hash)}>
              Xem trên explorer ↗
            </a>
          )}
        </div>
      )}
      {!tx.submitted && (
        <p className="mt-1.5 text-xs">
          Máy chủ đang chạy chế độ không nối chuỗi nên giao dịch <strong>chưa được gửi lên
          blockchain</strong>. Ví vẫn ký thật bằng khoá riêng của bạn, nhưng tham chiếu ở trên
          không tra cứu được trên explorer.
        </p>
      )}
    </Alert>
  );
}
