import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { api, type ResolvedDid } from "../../lib/api";
import { maskLabel } from "../../lib/constants";
import { Card, Alert, Mono, Badge, Field, Row } from "../../components/ui";

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
