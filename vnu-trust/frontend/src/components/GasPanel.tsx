import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useWallet } from "../hooks/useWallet";
import { useChainMode } from "../hooks/useChain";
import { faucet, getBalance, formatMove, chainConfigured, CHAIN } from "../lib/chain";
import { Card, Alert, Mono } from "./ui";

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
      <Card title="Gas cho giao dịch">
        <Alert tone="warn" title="Đang chạy chế độ không nối chuỗi">
          Máy chủ không xác minh giao dịch trên chuỗi nên giao diện cũng không gửi giao dịch nào
          lên. Không cần gas. Khi bật lại <span className="mono">VERIFY_ONCHAIN=true</span>, thẻ này
          sẽ hiện số dư và nút nhận token.
        </Alert>
      </Card>
    );
  }

  const bal = balance.data ?? 0n;
  const low = bal < LOW;

  const body = (
    <>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wide text-ink-500">Số dư gas</p>
          <p className="mt-1 text-3xl font-bold text-ink-900 tabular-nums">
            {balance.isLoading ? "…" : formatMove(bal)}
            <span className="ml-1.5 text-base font-semibold text-ink-400">MOVE</span>
          </p>
        </div>
        <button className="btn-primary" type="button" disabled={mint.isPending}
          onClick={() => mint.mutate()}>
          {mint.isPending ? "Đang nhận…" : "Nhận token thử nghiệm"}
        </button>
      </div>

      {low && !balance.isLoading && (
        <div className="mt-4">
          <Alert tone="warn" title="Sắp hết gas">
            Mỗi lần ký một giao dịch (đăng ký DID, cấp văn bằng, phê duyệt issuer…) đều tốn một ít
            phí. Bấm “Nhận token thử nghiệm” để tự nạp trước khi thao tác.
          </Alert>
        </div>
      )}

      {err && <div className="mt-4"><Alert tone="bad" title="Không nhận được token">{err}</Alert></div>}

      {!compact && (
        <p className="mt-4 text-xs text-ink-400 leading-relaxed">
          Token thử nghiệm chỉ để trả phí gọi hàm hợp đồng, không có giá trị và không chuyển được
          cho ai — hệ thống không có chức năng gửi token. Nguồn:{" "}
          <span className="mono">{CHAIN.faucet.replace(/^https?:\/\//, "")}</span> · ví{" "}
          <Mono value={wallet.address} />
        </p>
      )}
    </>
  );

  return compact ? <div>{body}</div> : <Card title="Gas cho giao dịch"
    subtitle="Tự nhận token thử nghiệm để ký được giao dịch on-chain.">{body}</Card>;
}
