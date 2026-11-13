import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type Credential } from "../../lib/api";
import { useChainTx } from "../../hooks/useChain";
import { ENTRY, bytesArg, u64Arg } from "../../lib/chain";
import { Card, Alert, Mono, Field, Row, StatusBadge } from "../../components/ui";
import TxProgress from "../../components/ChainTx";

/**
 * Cưỡng chế đổi trạng thái văn bằng — dùng khi có gian lận hoặc quyết định hành chính.
 *
 * Phải tra văn bằng ra trước khi thao tác, vì hàm trên chuỗi
 * (`admin_revoke_vc`, `admin_reinstate_vc`) nhận **số hiệu u64** do hợp đồng
 * cấp chứ không nhận chuỗi `urn:uuid:…`. Giao diện tự đọc số đó từ bản ghi;
 * bắt người dùng gõ tay thì gõ nhầm một chữ số là thu hồi nhầm bằng người khác.
 */
export default function CredentialsTab() {
  const qc = useQueryClient();
  const tx = useChainTx();
  const [vcId, setVcId] = useState("");
  const [reason, setReason] = useState("");
  const [vc, setVc] = useState<Credential | null>(null);
  const [err, setErr] = useState("");

  const find = useMutation({
    mutationFn: () => api.get<Credential>(`/admin/credentials/${encodeURIComponent(vcId.trim())}`),
    onSuccess: (d) => { setVc(d); setErr(""); tx.reset(); },
    onError: (e) => { setErr((e as Error).message); setVc(null); },
  });

  const onChainId = vc?.on_chain_vc_id ?? null;
  const canSign = onChainId !== null && onChainId > 0;

  const FN = { revoke: ENTRY.adminRevokeVc, suspend: ENTRY.adminSuspendVc, reinstate: ENTRY.adminReinstateVc };
  const act = (kind: keyof typeof FN) => {
    if (!vc || !canSign) return;
    void tx.run({
      fn: FN[kind],
      args: [u64Arg(onChainId!), bytesArg(reason.trim())],
      index: async (out) => {
        const r = await api.post(
          `/admin/credentials/${encodeURIComponent(vc.vc_id)}/${kind}`,
          { reason: reason.trim(), txHash: out.hash },
        );
        setReason("");
        find.mutate();
        qc.invalidateQueries({ queryKey: ["admin"] });
        return r;
      },
    });
  };

  return (
    <div className="space-y-6">
      <Card title="Tra văn bằng" subtitle="Nhập mã văn bằng để xem trạng thái và thao tác.">
        <form className="flex flex-col sm:flex-row gap-3 sm:items-end"
          onSubmit={(e) => { e.preventDefault(); find.mutate(); }}>
          <div className="flex-1">
            <Field label="Mã văn bằng (vcId)" value={vcId} onChange={setVcId} mono required
              placeholder="urn:uuid:…" />
          </div>
          <button className="btn-primary sm:w-36" type="submit" disabled={find.isPending}>
            {find.isPending ? "Đang tra…" : "Tra cứu"}
          </button>
        </form>
        {err && <div className="mt-4"><Alert tone="bad" title="Không tìm thấy">{err}</Alert></div>}
      </Card>

      {vc && (
        <Card title="Văn bằng">
          <dl className="grid sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
            <Row label="Trạng thái"><StatusBadge status={vc.status} /></Row>
            <Row label="Số hiệu trên chuỗi">
              {canSign
                ? <span className="mono">{onChainId}</span>
                : <span className="text-amber-700">không có</span>}
            </Row>
            <Row label="Đơn vị cấp"><Mono value={vc.issuer_did} /></Row>
            <Row label="Người sở hữu"><Mono value={vc.holder_did} /></Row>
            <Row label="Ngày cấp">{new Date(vc.issued_at).toLocaleString("vi-VN")}</Row>
            <Row label="Hạn dùng">
              {vc.expires_at ? new Date(vc.expires_at).toLocaleString("vi-VN") : "Vĩnh viễn"}
            </Row>
            <Row label="Mã giao dịch cấp"><Mono value={vc.tx_hash} /></Row>
            <Row label="CID nội dung"><Mono value={vc.ipfs_cid} /></Row>
          </dl>

          {!canSign && (
            <div className="mt-4">
              <Alert tone="warn" title="Không cưỡng chế được trên chuỗi">
                Bản ghi này không có số hiệu on-chain. Đây là văn bằng cấp từ thời giao diện còn
                ghi <span className="mono">onChainVcId = 0</span> vì không tự gửi giao dịch nên
                không đọc được sự kiện trả về. Những văn bằng cấp từ nay đều có số thật.
              </Alert>
            </div>
          )}

          <div className="mt-5 space-y-4">
            <Field label="Lý do (bắt buộc, ghi vào nhật ký kiểm toán)" value={reason}
              onChange={setReason} placeholder="Phát hiện sai sót hồ sơ" />
            <div className="flex flex-wrap gap-3">
              <button className="btn-danger" type="button"
                disabled={!canSign || reason.trim().length < 2 || tx.busy || vc.status === "revoked"}
                onClick={() => act("revoke")}>Ký &amp; thu hồi</button>
              <button className="btn-ghost" type="button"
                disabled={!canSign || reason.trim().length < 2 || tx.busy || vc.status !== "active"}
                onClick={() => act("suspend")}>Ký &amp; tạm ngưng</button>
              <button className="btn-ghost" type="button"
                disabled={!canSign || reason.trim().length < 2 || tx.busy || vc.status !== "suspended"}
                onClick={() => act("reinstate")}>Ký &amp; kích hoạt lại</button>
            </div>
            <p className="text-xs text-ink-400">
              Thu hồi là vĩnh viễn — hợp đồng không cho đổi trạng thái của văn bằng đã thu hồi.
              Tạm ngưng chỉ áp dụng cho văn bằng đang hiệu lực, và chỉ admin kích hoạt lại được.
              Văn bằng đã hết hạn chỉ còn thu hồi được.
            </p>
          </div>

          <div className="mt-4"><TxProgress tx={tx} okTitle="Đã cập nhật trạng thái văn bằng" /></div>
        </Card>
      )}
    </div>
  );
}
