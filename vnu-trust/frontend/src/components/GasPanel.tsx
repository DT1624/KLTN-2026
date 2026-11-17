import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useWallet } from "../hooks/useWallet";
import { useChainMode } from "../hooks/useChain";
import { faucet, getBalance, formatMove, chainConfigured } from "../lib/chain";
import { Section, Alert, Mono } from "./ui";

/** Dưới mức này thì một vài giao dịch nữa là hết — nhắc người dùng nạp trước. */
const LOW = 20_000_000n;

/**
 * TỰ PHỤC VỤ GAS.
 *
 * Gọi hàm entry trên chuỗi nào cũng tốn phí, nên mỗi tài khoản phải có một ít
 * token testnet. Thẻ này để họ **tự xin cho chính mình** bằng một nút bấm.
 *
 * ĐÂY KHÔNG PHẢI VÍ TIỀN: không có chuyển khoản, không có người nhận, không có
 * số tiền để gõ. Hệ thống không hề có chức năng gửi token giữa các tài khoản —
 * token duy nhất chạm tới ở đây là phí gas của chính mình.
 */
export default function GasPanel({ compact = false }: { compact?: boolean }) {
  const { wallet } = useWallet();
  const { live } = useChainMode();
  const qc = useQueryClient();
  const [err, setErr] = useState("");

  const balance = useQuery({
    queryKey: ["chain", "balance", wallet?.address],
    queryFn: () => getBalance(wallet!.address),
    enabled: Boolean(wallet) && live && chainConfigured(),
    refetchInterval: 30_000,
  });

  const mint = useMutation({
    mutationFn: () => faucet(wallet!.address),
    onSuccess: () => { setErr(""); qc.invalidateQueries({ queryKey: ["chain", "balance"] }); },
    onError: (e) => setErr((e as Error).message),
  });

  if (!wallet) return null;

  if (!live || !chainConfigured()) {
    if (compact) return null;
    return (
      <Section title="Phí giao dịch">
        <Alert tone="warn">
          Đang ở chế độ thử, chưa nối chuỗi. Không cần phí giao dịch.
        </Alert>
      </Section>
    );
  }

  const bal = balance.data ?? 0n;
  const low = bal < LOW;

  const body = (
    <>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="label">Số dư</p>
          <p className="mt-1 text-2xl font-bold tabular-nums">
            {balance.isLoading ? "…" : formatMove(bal)}
            <span className="ml-1.5 text-base font-semibold text-muted">MOVE</span>
          </p>
        </div>
        <button className="btn-secondary" type="button" disabled={mint.isPending}
          onClick={() => mint.mutate()}>
          {mint.isPending ? "Đang nhận…" : "Nhận token thử nghiệm"}
        </button>
      </div>

      <div role="status" aria-live="polite">
        {mint.isSuccess && !mint.isPending && !err && (
          <p className="mt-4 text-sm">Đã nhận token thử nghiệm</p>
        )}
      </div>

      {low && !balance.isLoading && (
        <div className="mt-4">
          <Alert tone="warn" title="Sắp hết phí giao dịch">
            Mỗi lần ký một giao dịch (đăng ký DID, cấp văn bằng, phê duyệt đơn vị cấp bằng) đều tốn
            một ít phí. Bấm “Nhận token thử nghiệm” để tự nạp trước khi thao tác.
          </Alert>
        </div>
      )}

      {err && <div className="mt-4"><Alert tone="bad" title="Không nhận được token">{err}</Alert></div>}

      {!compact && (
        <p className="mt-4 text-sm text-muted max-w-prose">
          Token thử nghiệm chỉ để trả phí giao dịch, không có giá trị và không chuyển được
          cho ai. Ví của bạn: <Mono value={wallet.address} />
        </p>
      )}
    </>
  );

  return compact
    ? <div className="rounded-sheet border border-rule p-4 bg-sheet">{body}</div>
    : (
      <Section title="Phí giao dịch"
        description="Mỗi lần ký cần một ít token MOVE để trả phí. Trên mạng thử nghiệm, bạn nhận miễn phí.">
        {body}
      </Section>
    );
}
