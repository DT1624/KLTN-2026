import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type Credential } from "../../lib/api";
import { useChainTx } from "../../hooks/useChain";
import { ENTRY, bytesArg, u64Arg } from "../../lib/chain";
import { Card, Alert, Mono, Field, Row, StatusBadge } from "../../components/ui";
import TxProgress from "../../components/ChainTx";
import ReviewPanel from "../../components/ReviewPanel";

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
  // Số hiệu trên chuỗi BẮT ĐẦU TỪ 0 — văn bằng đầu tiên của gói có id 0. Điều
  // kiện cũ `> 0` (từ thời giao diện ghi cứng onChainVcId = 0) chặn nhầm nó.
  const canSign = onChainId !== null;

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
      <ReviewPanel mode="admin" />
      <LinkReplacementCard />
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
            {vc.replaces_vc_id && <Row label="Thay cho văn bằng"><Mono value={vc.replaces_vc_id} /></Row>}
            {vc.replaced_by_vc_id && <Row label="Đã được thay bằng"><Mono value={vc.replaced_by_vc_id} /></Row>}
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

/**
 * Nối liên kết thay thế (admin_link_replacement, C3) khi đơn vị cấp văn bằng cũ
 * đã mất quyền: một đơn vị khác cấp văn bằng mới bằng issue_vc, admin nối hai bản
 * ghi. Văn bằng cũ bị thu hồi với lý do "replaced" nếu chưa thu hồi; đã thu hồi
 * (vd. vì gian lận) thì giữ nguyên lý do cũ — đúng như hợp đồng.
 */
function LinkReplacementCard() {
  const qc = useQueryClient();
  const tx = useChainTx();
  const [oldId, setOldId] = useState("");
  const [newId, setNewId] = useState("");
  const [pair, setPair] = useState<[Credential, Credential] | null>(null);
  const [err, setErr] = useState("");

  const load = useMutation({
    mutationFn: () => Promise.all([
      api.get<Credential>(`/admin/credentials/${encodeURIComponent(oldId.trim())}`),
      api.get<Credential>(`/admin/credentials/${encodeURIComponent(newId.trim())}`),
    ]),
    onSuccess: (d) => { setPair(d); setErr(""); tx.reset(); },
    onError: (e) => { setErr((e as Error).message); setPair(null); },
  });

  const [o, n] = pair ?? [null, null];
  const problem = !o || !n ? ""
    : o.on_chain_vc_id == null || n.on_chain_vc_id == null ? "Có văn bằng chưa có số hiệu trên chuỗi"
      : n.on_chain_vc_id <= o.on_chain_vc_id ? "Văn bằng thay thế phải được cấp sau văn bằng cũ"
        : n.vc_type !== o.vc_type ? "Hai văn bằng khác loại"
          : n.status !== "active" ? "Văn bằng thay thế không còn hiệu lực"
            : o.replaced_by_vc_id ? "Văn bằng cũ đã có bản thay thế"
              : n.replaces_vc_id ? "Văn bằng mới đã thay cho văn bằng khác" : "";

  const link = () => {
    if (!o || !n || problem) return;
    void tx.run({
      fn: ENTRY.adminLinkReplacement,
      args: [u64Arg(o.on_chain_vc_id!), u64Arg(n.on_chain_vc_id!)],
      index: async (out) => {
        const r = await api.post(`/admin/credentials/${encodeURIComponent(o.vc_id)}/replacement`,
          { newVcId: n.vc_id, txHash: out.hash });
        load.mutate();
        qc.invalidateQueries({ queryKey: ["admin"] });
        return r;
      },
    });
  };

  return (
    <Card title="Nối văn bằng thay thế"
      subtitle="Dùng khi đơn vị cấp văn bằng cũ đã mất quyền và một đơn vị khác đã cấp văn bằng mới.">
      <form className="grid sm:grid-cols-[1fr_1fr_auto] gap-3 items-end"
        onSubmit={(e) => { e.preventDefault(); load.mutate(); }}>
        <Field label="Văn bằng cũ (vcId)" value={oldId} onChange={setOldId} mono required placeholder="urn:uuid:…" />
        <Field label="Văn bằng mới (vcId)" value={newId} onChange={setNewId} mono required placeholder="urn:uuid:…" />
        <button className="btn-ghost" type="submit" disabled={load.isPending}>Kiểm tra</button>
      </form>
      {err && <div className="mt-4"><Alert tone="bad" title="Không tìm thấy">{err}</Alert></div>}
      {o && n && (
        <div className="mt-4 space-y-3 text-sm">
          <p>Số hiệu <span className="mono">{o.on_chain_vc_id}</span> → <span className="mono">{n.on_chain_vc_id}</span>
            {" · "}holder {o.holder_address === n.holder_address ? "giữ nguyên" : "đổi sang ví mới (DID cũ phải đã bị khoá/thu hồi)"}</p>
          {problem
            ? <Alert tone="warn" title="Không nối được">{problem}</Alert>
            : <button className="btn-primary" type="button" disabled={tx.busy} onClick={link}>Ký &amp; nối liên kết</button>}
          <TxProgress tx={tx} okTitle="Đã nối văn bằng thay thế" />
        </div>
      )}
    </Card>
  );
}
