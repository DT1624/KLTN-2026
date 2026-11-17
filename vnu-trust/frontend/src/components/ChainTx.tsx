import { useRef } from "react";
import type { ReactNode } from "react";
import { explorerTxUrl } from "../lib/chain";
import type { ChainTx, TxStep } from "../hooks/useChain";
import { Alert, Mono } from "./ui";
import { IconCheck, IconExternal } from "./icons";
import Seal from "./Seal";

type Phase = "draft" | "signing" | "done" | "error";

/**
 * Tờ chứa biểu mẫu sắp ký. Viền đổi theo tiến trình: nét đứt (nháp), liền mực
 * (đang ký), liền mực có dấu (đã ghi lên chuỗi), liền son (lỗi). Viền chỉ là tín
 * hiệu phụ; tín hiệu chính là danh sách bước trong `TxProgress`.
 */
export function SignSheet({ tx, phase, className = "", children }: {
  tx?: ChainTx;
  phase?: Phase;
  className?: string;
  children: ReactNode;
}) {
  const p: Phase =
    phase ??
    (!tx || tx.step === "idle" ? "draft" : tx.busy ? "signing" : tx.step === "done" ? "done" : "error");
  const border = {
    draft: "border-dashed border-pencil",
    signing: "border-solid border-primary",
    done: "border-solid border-success",
    error: "border-solid border-son",
  }[p];
  return (
    <div className={`bg-sheet rounded-sheet shadow-card relative p-5 sm:p-6 border-[1.5px] transition-colors ${border} ${className}`}>
      {p === "done" && tx?.submitted && (
        <div className="absolute top-3 right-3 pointer-events-none">
          <Seal size={44} />
        </div>
      )}
      {children}
    </div>
  );
}

const STEPS: { step: TxStep; label: string; optional: boolean }[] = [
  { step: "preparing", label: "Chuẩn bị dữ liệu", optional: true },
  { step: "gas", label: "Kiểm tra phí giao dịch", optional: true },
  { step: "signing", label: "Ký bằng khoá trong ví", optional: false },
  { step: "waiting", label: "Chờ chuỗi xác nhận", optional: false },
  { step: "indexing", label: "Ghi vào chỉ mục", optional: false },
];

/**
 * Hiển thị tiến trình một lượt ký và gửi giao dịch.
 *
 * Thay cho ô "dán mã giao dịch" ngày trước: người dùng bấm nút, ví ký, giao
 * dịch lên chuỗi, và mã giao dịch **hiện ra** như kết quả chứ không phải là
 * thứ họ phải tự đi tìm rồi nhập vào.
 */
export default function TxProgress({ tx, okTitle = "Đã ghi lên chuỗi" }: { tx: ChainTx; okTitle?: string }) {
  // Các bước đã từng xảy ra trong lượt này: bước tuỳ chọn chỉ hiện nếu đã có.
  const seen = useRef<Set<TxStep>>(new Set());
  if (tx.step === "idle") seen.current.clear();
  else seen.current.add(tx.step);

  if (tx.step === "idle") return null;

  if (tx.busy) {
    const currentIdx = STEPS.findIndex((s) => s.step === tx.step);
    const shown = STEPS.filter((s) => !s.optional || seen.current.has(s.step));
    return (
      <div role="status" aria-live="polite" className="mt-4">
        <ol className="space-y-1.5 text-sm rounded-sheet border border-rule bg-paper p-3">
          {shown.map((s) => {
            const idx = STEPS.findIndex((x) => x.step === s.step);
            const state = idx < currentIdx ? "past" : idx === currentIdx ? "now" : "next";
            return (
              <li key={s.step} aria-current={state === "now" ? "step" : undefined}
                className={`flex items-center gap-2 ${
                  state === "now" ? "text-primary font-semibold" : state === "past" ? "text-ink-2" : "text-muted"
                }`}>
                <span className="w-4 h-4 shrink-0 inline-flex items-center justify-center">
                  {state === "past" && <IconCheck className="w-4 h-4 text-success" />}
                  {state === "now" && (
                    <span aria-hidden
                      className="w-3.5 h-3.5 rounded-full border-2 border-primary/30 border-t-primary animate-spin motion-reduce:hidden" />
                  )}
                </span>
                <span>{s.label}{state === "now" ? <span className="hidden motion-reduce:inline">, đang thực hiện</span> : null}</span>
              </li>
            );
          })}
        </ol>
      </div>
    );
  }

  if (tx.step === "error") {
    return (
      <div className="mt-4">
        <Alert tone="bad" title="Chưa thực hiện được">{tx.error}</Alert>
      </div>
    );
  }

  return (
    <div className="mt-4" role="status" aria-live="polite">
      <Alert tone={tx.submitted ? "ok" : "warn"} title={okTitle}>
        {tx.hash && (
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span>{tx.submitted ? "Mã giao dịch" : "Tham chiếu cục bộ"}</span>
            <Mono value={tx.hash} />
            {tx.submitted && (
              <a className="link inline-flex items-center gap-1" target="_blank" rel="noreferrer"
                href={explorerTxUrl(tx.hash)}>
                Xem trên trình duyệt khối <IconExternal />
              </a>
            )}
          </div>
        )}
        {!tx.submitted && (
          <p className="mt-2">
            Máy chủ đang ở chế độ thử nên giao dịch chưa được gửi lên chuỗi. Ví vẫn ký bằng khoá
            riêng của bạn, nhưng tham chiếu này không tra được trên trình duyệt khối.
          </p>
        )}
      </Alert>
    </div>
  );
}
