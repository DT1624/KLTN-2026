import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type Credential } from "../../lib/api";
import { useChainTx } from "../../hooks/useChain";
import { ENTRY, bytesArg, u64Arg } from "../../lib/chain";
import { Section, Alert, Mono, Field, Row, StatusBadge } from "../../components/ui";
import TxProgress, { SignSheet } from "../../components/ChainTx";
import Rosette from "../../components/Rosette";
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
  const OK_TITLE = {
    revoke: "Đã thu hồi văn bằng",
    suspend: "Đã tạm ngưng văn bằng",
    reinstate: "Đã kích hoạt lại văn bằng",
  };
  const [lastKind, setLastKind] = useState<keyof typeof FN>("revoke");
  const act = (kind: keyof typeof FN) => {
    if (!vc || !canSign) return;
    setLastKind(kind);
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
      <Section title="Tra văn bằng" description="Nhập mã văn bằng để xem trạng thái và thao tác.">
        <form className="flex flex-col sm:flex-row gap-3 sm:items-end"
          onSubmit={(e) => { e.preventDefault(); find.mutate(); }}>
          <div className="flex-1">
            <Field label="Mã văn bằng" value={vcId} onChange={setVcId} mono required
              placeholder="urn:uuid:…" />
          </div>
          <button className="btn-secondary sm:w-40" type="submit" disabled={find.isPending}>
            {find.isPending ? "Đang tra…" : "Tra văn bằng"}
          </button>
        </form>
        {err && <div className="mt-4" role="status" aria-live="polite"><Alert tone="bad" title="Không tìm thấy">{err}</Alert></div>}

        {vc && (
          <>
          <div className="sheet p-5 sm:p-6 mt-5" role="status" aria-live="polite">
            <div className="flex flex-wrap items-center gap-4 mb-4">
              <Rosette seed={vc.vc_id} size={64} />
              <div className="min-w-0 space-y-1">
                <h3 className="text-base font-semibold">Văn bằng</h3>
                <Mono value={vc.vc_id} />
                <div><StatusBadge status={vc.status} /></div>
              </div>
            </div>
            <dl className="grid sm:grid-cols-2 gap-x-6 gap-y-3">
              <Row label="Số hiệu trên chuỗi">
                {canSign
                  ? <span className="hex">{onChainId}</span>
                  : "Không có"}
              </Row>
              <Row label="Đơn vị cấp"><Mono value={vc.issuer_did} /></Row>
              <Row label="Người học"><Mono value={vc.holder_did} /></Row>
              <Row label="Ngày cấp">{new Date(vc.issued_at).toLocaleString("vi-VN")}</Row>
              <Row label="Hạn dùng">
                {vc.expires_at ? new Date(vc.expires_at).toLocaleString("vi-VN") : "Vĩnh viễn"}
              </Row>
              <Row label="Mã giao dịch cấp"><Mono value={vc.tx_hash} /></Row>
              {vc.replaces_vc_id && <Row label="Thay cho văn bằng"><Mono value={vc.replaces_vc_id} /></Row>}
              {vc.replaced_by_vc_id && <Row label="Đã được thay bằng"><Mono value={vc.replaced_by_vc_id} /></Row>}
              <Row label="Mã nội dung (CID)"><Mono value={vc.ipfs_cid} /></Row>
            </dl>

            {!canSign && (
              <div className="mt-4">
                <Alert tone="warn" title="Không thao tác được trên chuỗi">
                  Văn bằng này chưa có số hiệu trên chuỗi (được cấp ở chế độ thử), nên không thao tác
                  trên chuỗi được.
                </Alert>
              </div>
            )}
          </div>

          <SignSheet tx={tx} className="mt-4">
            <div className="space-y-4">
              <Field label="Lý do (bắt buộc, ghi vào nhật ký kiểm toán)" value={reason}
                onChange={setReason} placeholder="Phát hiện sai sót hồ sơ" />
              <div className="flex flex-wrap gap-3">
                <button className="btn-danger" type="button"
                  disabled={!canSign || reason.trim().length < 2 || tx.busy || vc.status === "revoked"}
                  onClick={() => act("revoke")}>Ký và thu hồi</button>
                <button className="btn-secondary" type="button"
                  disabled={!canSign || reason.trim().length < 2 || tx.busy || vc.status !== "active"}
                  onClick={() => act("suspend")}>Ký và tạm ngưng</button>
                <button className="btn-primary" type="button"
                  disabled={!canSign || reason.trim().length < 2 || tx.busy || vc.status !== "suspended"}
                  onClick={() => act("reinstate")}>Ký và kích hoạt lại</button>
              </div>
              <p className="text-sm text-muted max-w-prose">
                Thu hồi là vĩnh viễn: sổ đăng ký không cho đổi trạng thái của văn bằng đã thu hồi.
                Tạm ngưng chỉ áp dụng cho văn bằng đang hiệu lực, và chỉ quản trị viên kích hoạt lại
                được. Văn bằng đã hết hạn chỉ còn thu hồi được.
              </p>
              <TxProgress tx={tx} okTitle={OK_TITLE[lastKind]} />
            </div>
          </SignSheet>
          </>
        )}
      </Section>
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
    <Section title="Nối văn bằng thay thế"
      description="Dùng khi đơn vị cấp văn bằng cũ đã mất quyền và một đơn vị khác đã cấp văn bằng mới.">
      <form className="grid sm:grid-cols-[1fr_1fr_auto] gap-3 items-end"
        onSubmit={(e) => { e.preventDefault(); load.mutate(); }}>
        <Field label="Văn bằng cũ" value={oldId} onChange={setOldId} mono required placeholder="urn:uuid:…" />
        <Field label="Văn bằng mới" value={newId} onChange={setNewId} mono required placeholder="urn:uuid:…" />
        <button className="btn-secondary" type="submit" disabled={load.isPending}>Kiểm tra</button>
      </form>
      {err && <div className="mt-4" role="status" aria-live="polite"><Alert tone="bad" title="Không tìm thấy">{err}</Alert></div>}
      {o && n && (
        <SignSheet tx={tx} className="mt-5">
          <div className="space-y-3">
            <p>
              Văn bằng số <span className="hex">{o.on_chain_vc_id}</span> được thay bằng văn bằng số{" "}
              <span className="hex">{n.on_chain_vc_id}</span>.
            </p>
            <p className="text-muted">
              {o.holder_address === n.holder_address
                ? "Người học giữ nguyên ví."
                : "Người học đổi sang ví mới (DID của ví cũ phải đã bị khoá hoặc thu hồi)."}
            </p>
            {problem
              ? <Alert tone="warn" title="Không nối được">{problem}</Alert>
              : <button className="btn-primary" type="button" disabled={tx.busy} onClick={link}>Ký và nối văn bằng thay thế</button>}
            <TxProgress tx={tx} okTitle="Đã nối văn bằng thay thế" />
          </div>
        </SignSheet>
      )}
    </Section>
  );
}
