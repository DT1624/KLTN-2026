import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type ResolvedDid } from "../../lib/api";
import { maskLabel } from "../../lib/constants";
import { useChainTx } from "../../hooks/useChain";
import { ENTRY, bytesArg } from "../../lib/chain";
import { Card, Alert, Mono, Badge, Field, Row } from "../../components/ui";
import TxProgress from "../../components/ChainTx";

export interface RoleSnapshot {
  address: string;
  isActiveAdmin: boolean;
  isActiveIssuer: boolean;
  canDelegate: boolean;
  role: {
    approvedBy: string; vcTypeMask: number; delegationVcCid: string;
    delegationVcHash: string; expiresAt: number; status: string;
  } | null;
  appRole: string | null;
  appLabel: string | null;
  liveCredentials: { issued: number; held: number };
  source: string;
}

/**
 * Tra cứu danh tính: quyền thật của một địa chỉ và tài liệu DID của nó.
 *
 * Đây là chỗ nhìn ra chỗ lệch giữa vai trò **khai trong ứng dụng** và quyền
 * **thật trên chuỗi** — hai thứ hoàn toàn có thể khác nhau, vì ai cũng tự đăng
 * ký vai trò được khi tạo ví, còn quyền thì phải do hợp đồng cấp.
 */
export default function IdentitiesTab() {
  return (
    <div className="space-y-6">
      <CheckAddressCard />
      <ModerateDidCard />
      <ResolveDidCard />
    </div>
  );
}

function CheckAddressCard() {
  const [address, setAddress] = useState("");
  const [result, setResult] = useState<RoleSnapshot | null>(null);
  const [err, setErr] = useState("");

  const check = useMutation({
    mutationFn: () =>
      api.get<RoleSnapshot>(`/admin/authority/role/${encodeURIComponent(address.trim())}`),
    onSuccess: (d) => { setResult(d); setErr(""); },
    onError: (e) => { setErr((e as Error).message); setResult(null); },
  });

  return (
    <Card title="Tra cứu quyền theo địa chỉ"
      subtitle="Đọc trực tiếp từ hợp đồng — không phụ thuộc vai trò khai trong ứng dụng.">
      <form className="flex flex-col sm:flex-row gap-3 sm:items-end"
        onSubmit={(e) => { e.preventDefault(); check.mutate(); }}>
        <div className="flex-1">
          <Field label="Địa chỉ ví" value={address} onChange={setAddress} mono placeholder="0x…" required />
        </div>
        <button className="btn-primary sm:w-36" type="submit" disabled={check.isPending}>
          {check.isPending ? "Đang tra…" : "Tra cứu"}
        </button>
      </form>

      {err && <div className="mt-4"><Alert tone="bad" title="Không tra cứu được">{err}</Alert></div>}

      {result && (
        <div className="mt-5 space-y-3">
          <Mono value={result.address} truncate={false} />
          <div className="flex flex-wrap gap-2">
            {result.isActiveAdmin
              ? <Badge tone="ok">Admin đang hoạt động</Badge>
              : <Badge tone="muted">Không phải admin</Badge>}
            {result.isActiveIssuer
              ? <Badge tone="ok">Issuer đang hoạt động</Badge>
              : <Badge tone="muted">Không phải issuer</Badge>}
            {result.canDelegate && <Badge tone="info">Được uỷ quyền lại</Badge>}
            {result.appRole && <Badge tone="muted">Vai trò trong ứng dụng: {result.appRole}</Badge>}
          </div>

          <dl className="grid sm:grid-cols-2 gap-x-6 gap-y-3 text-sm pt-1">
            <Row label="Văn bằng đã cấp (còn hiệu lực)">{result.liveCredentials?.issued ?? 0}</Row>
            <Row label="Văn bằng đang giữ (còn hiệu lực)">{result.liveCredentials?.held ?? 0}</Row>
            {result.role && (
              <>
                <Row label="Loại được phép cấp">{maskLabel(result.role.vcTypeMask)}</Row>
                <Row label="Hạn uỷ quyền">
                  {result.role.expiresAt === 0
                    ? "Vĩnh viễn"
                    : new Date(result.role.expiresAt * 1000).toLocaleString("vi-VN")}
                </Row>
                <Row label="Người phê duyệt"><Mono value={result.role.approvedBy} /></Row>
                <Row label="Trạng thái bản ghi">{result.role.status}</Row>
              </>
            )}
          </dl>

          <p className="text-xs text-ink-400">
            Nguồn dữ liệu: {result.source === "chain" ? "đọc trực tiếp từ chuỗi" : "chỉ mục CSDL"}
          </p>
        </div>
      )}
    </Card>
  );
}

/**
 * Admin khoá / mở / thu hồi DID của một địa chỉ (admin_*_did).
 *
 * Hai hệ quả của hợp đồng cần nói rõ cho người bấm:
 *  - Thu hồi DID thu hồi luôn quyền admin/issuer của địa chỉ đó (M-01) — chủ có
 *    đăng ký DID mới thì cũng chỉ là một danh tính trắng.
 *  - Chủ đã tự khoá thì admin vẫn khoá được (tiếp quản, M-08); khi đó chủ không
 *    tự mở lại được nữa. Ngược lại, DID chủ tự khoá thì admin KHÔNG mở thay được.
 * Admin thường không đụng được DID của root hay admin khác — hợp đồng sẽ từ chối.
 */
function ModerateDidCard() {
  const qc = useQueryClient();
  const tx = useChainTx();
  const [address, setAddress] = useState("");
  const [reason, setReason] = useState("");
  const [did, setDid] = useState<ResolvedDid | null>(null);
  const [err, setErr] = useState("");

  const find = useMutation({
    mutationFn: () => api.get<ResolvedDid>(`/did/by-address/${encodeURIComponent(address.trim())}`),
    onSuccess: (d) => { setDid(d); setErr(""); tx.reset(); },
    onError: (e) => { setErr((e as Error).message); setDid(null); },
  });

  const FN = { suspended: ENTRY.adminSuspendDid, active: ENTRY.adminReactivateDid, revoked: ENTRY.adminRevokeDid };
  const act = (status: keyof typeof FN) => {
    const target = address.trim();
    void tx.run({
      fn: FN[status],
      args: [target, bytesArg(reason.trim())],
      index: async (out) => {
        const r = await api.post(`/admin/dids/${encodeURIComponent(target)}/status`,
          { status, reason: reason.trim(), txHash: out.hash });
        setReason("");
        find.mutate();
        qc.invalidateQueries({ queryKey: ["admin"] });
        return r;
      },
    });
  };
  const ready = !!did && reason.trim().length >= 2 && !tx.busy;

  return (
    <Card title="Kiểm duyệt DID"
      subtitle="Khoá, mở khoá hoặc thu hồi danh tính của một địa chỉ — ký bằng ví admin.">
      <form className="flex flex-col sm:flex-row gap-3 sm:items-end"
        onSubmit={(e) => { e.preventDefault(); find.mutate(); }}>
        <div className="flex-1">
          <Field label="Địa chỉ ví" value={address} onChange={setAddress} mono placeholder="0x…" required />
        </div>
        <button className="btn-primary sm:w-36" type="submit" disabled={find.isPending}>
          {find.isPending ? "Đang tra…" : "Tra DID"}
        </button>
      </form>
      {err && <div className="mt-4"><Alert tone="bad" title="Không tìm thấy DID">{err}</Alert></div>}

      {did && (
        <div className="mt-5 space-y-4">
          <dl className="grid sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
            <Row label="DID"><Mono value={did.did} /></Row>
            <Row label="Trạng thái"><Badge tone={did.status === "active" ? "ok" : "warn"}>{did.status}</Badge></Row>
          </dl>
          <Field label="Lý do (bắt buộc, ghi lên chuỗi và nhật ký kiểm toán)" value={reason}
            onChange={setReason} placeholder="Nghi lộ khoá riêng" />
          <div className="flex flex-wrap gap-3">
            <button className="btn-ghost" type="button" disabled={!ready || did.status === "revoked"}
              onClick={() => act("suspended")}>Ký &amp; khoá</button>
            <button className="btn-ghost" type="button" disabled={!ready || did.status !== "suspended"}
              onClick={() => act("active")}>Ký &amp; mở khoá</button>
            <button className="btn-danger" type="button" disabled={!ready || did.status === "revoked"}
              onClick={() => act("revoked")}>Ký &amp; thu hồi</button>
          </div>
          <p className="text-xs text-ink-400">
            Thu hồi là vĩnh viễn và <strong>thu hồi luôn quyền admin/issuer</strong> của địa chỉ này.
            Văn bằng đã cấp không tự mất hiệu lực — thu hồi riêng ở tab Văn bằng nếu có gian lận.
            DID do chính chủ tự khoá thì admin không mở thay được; admin khoá đè lên thì chủ
            không tự mở được nữa.
          </p>
          <TxProgress tx={tx} okTitle="Đã cập nhật trạng thái DID" />
        </div>
      )}
    </Card>
  );
}

function ResolveDidCard() {
  const [did, setDid] = useState("");
  const [result, setResult] = useState<ResolvedDid | null>(null);
  const [err, setErr] = useState("");

  const resolve = useMutation({
    mutationFn: () => api.get<ResolvedDid>(`/did/resolve?did=${encodeURIComponent(did.trim())}`),
    onSuccess: (d) => { setResult(d); setErr(""); },
    onError: (e) => { setErr((e as Error).message); setResult(null); },
  });

  return (
    <Card title="Tra cứu tài liệu DID"
      subtitle="Xem bản ghi DID và kiểm tra nội dung có còn khớp bản neo trên chuỗi không.">
      <form className="flex flex-col sm:flex-row gap-3 sm:items-end"
        onSubmit={(e) => { e.preventDefault(); resolve.mutate(); }}>
        <div className="flex-1">
          <Field label="DID" value={did} onChange={setDid} mono required
            placeholder="did:vnu:holder:0x…" />
        </div>
        <button className="btn-primary sm:w-36" type="submit" disabled={resolve.isPending}>
          {resolve.isPending ? "Đang tra…" : "Tra cứu"}
        </button>
      </form>

      {err && <div className="mt-4"><Alert tone="bad" title="Không tra cứu được">{err}</Alert></div>}

      {result && (
        <dl className="mt-5 grid sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
          <Row label="Trạng thái"><Badge tone={result.status === "active" ? "ok" : "warn"}>{result.status}</Badge></Row>
          <Row label="Phiên bản">{result.version}</Row>
          <Row label="CID tài liệu"><Mono value={result.documentCid} /></Row>
          <Row label="Toàn vẹn nội dung">
            {result.integrityOk === null
              ? <Badge tone="muted">Chưa kiểm được</Badge>
              : result.integrityOk
                ? <Badge tone="ok">Khớp bản neo</Badge>
                : <Badge tone="bad">Nội dung đã bị sửa</Badge>}
          </Row>
          <Row label="Nguồn">{result.source === "chain" ? "Chuỗi" : "Chỉ mục CSDL"}</Row>
        </dl>
      )}
    </Card>
  );
}
