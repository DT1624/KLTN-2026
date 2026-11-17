import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type ResolvedDid } from "../../lib/api";
import { maskLabel } from "../../lib/constants";
import { useChainTx } from "../../hooks/useChain";
import { ENTRY, bytesArg } from "../../lib/chain";
import {
  Card, Section, Alert, Mono, Badge, Field, Row,
  DidStatusBadge, RoleStatusBadge, roleLabel,
} from "../../components/ui";
import TxProgress, { SignSheet } from "../../components/ChainTx";
import Rosette from "../../components/Rosette";

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
      <MigrationCard />
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
    <Section title="Tra cứu quyền theo địa chỉ"
      description="Đọc trực tiếp từ sổ đăng ký trên chuỗi, không phụ thuộc vai trò khai trong ứng dụng.">
      <form className="flex flex-col sm:flex-row gap-3 sm:items-end"
        onSubmit={(e) => { e.preventDefault(); check.mutate(); }}>
        <div className="flex-1">
          <Field label="Địa chỉ ví" value={address} onChange={setAddress} mono placeholder="0x…" required />
        </div>
        <button className="btn-secondary sm:w-36" type="submit" disabled={check.isPending}>
          {check.isPending ? "Đang tra…" : "Tra cứu"}
        </button>
      </form>

      <div role="status" aria-live="polite">
        {err && <div className="mt-4"><Alert tone="bad" title="Không tra cứu được">{err}</Alert></div>}

        {result && (
          <div className="sheet p-5 mt-5 space-y-3">
            <Mono value={result.address} truncate={false} />
            <div className="flex flex-wrap gap-2">
              {result.isActiveAdmin
                ? <Badge tone="ok">Quản trị viên đang hoạt động</Badge>
                : <Badge tone="muted">Không phải quản trị viên</Badge>}
              {result.isActiveIssuer
                ? <Badge tone="ok">Đơn vị cấp bằng đang hoạt động</Badge>
                : <Badge tone="muted">Không phải đơn vị cấp bằng</Badge>}
              {result.canDelegate && <Badge tone="info">Được uỷ quyền lại</Badge>}
              {result.appRole && <Badge tone="muted">Vai trò trong ứng dụng: {roleLabel(result.appRole)}</Badge>}
            </div>

            <dl className="grid sm:grid-cols-2 gap-x-6 gap-y-3 pt-1">
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
                  <Row label="Trạng thái bản ghi"><RoleStatusBadge status={result.role.status} /></Row>
                </>
              )}
            </dl>

            <p className="text-sm text-muted">
              Nguồn dữ liệu: {result.source === "chain" ? "đọc trực tiếp từ chuỗi" : "chỉ mục cơ sở dữ liệu"}
            </p>
          </div>
        )}
      </div>
    </Section>
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
  const OK_TITLE = { suspended: "Đã khoá DID", active: "Đã mở khoá DID", revoked: "Đã thu hồi DID" };
  const [lastStatus, setLastStatus] = useState<keyof typeof FN>("suspended");
  const act = (status: keyof typeof FN) => {
    setLastStatus(status);
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
    <Section title="Kiểm duyệt DID"
      description="Khoá, mở khoá hoặc thu hồi danh tính của một địa chỉ, ký bằng ví quản trị viên.">
      <form className="flex flex-col sm:flex-row gap-3 sm:items-end"
        onSubmit={(e) => { e.preventDefault(); find.mutate(); }}>
        <div className="flex-1">
          <Field label="Địa chỉ ví" value={address} onChange={setAddress} mono placeholder="0x…" required />
        </div>
        <button className="btn-secondary sm:w-36" type="submit" disabled={find.isPending}>
          {find.isPending ? "Đang tra…" : "Tra DID"}
        </button>
      </form>
      {err && <div className="mt-4" role="status" aria-live="polite"><Alert tone="bad" title="Không tìm thấy DID">{err}</Alert></div>}

      {did && (
        <SignSheet tx={tx} className="mt-5">
          <div className="space-y-4">
            <dl className="grid sm:grid-cols-2 gap-x-6 gap-y-3">
              <Row label="DID"><Mono value={did.did} /></Row>
              <Row label="Trạng thái"><DidStatusBadge status={did.status} /></Row>
            </dl>
            <Field label="Lý do (bắt buộc, ghi lên chuỗi và nhật ký kiểm toán)" value={reason}
              onChange={setReason} placeholder="Nghi lộ khoá riêng" />
            <div className="flex flex-wrap gap-3">
              <button className="btn-secondary" type="button" disabled={!ready || did.status === "revoked"}
                onClick={() => act("suspended")}>Ký và khoá DID</button>
              <button className="btn-primary" type="button" disabled={!ready || did.status !== "suspended"}
                onClick={() => act("active")}>Ký và mở khoá DID</button>
              <button className="btn-danger" type="button" disabled={!ready || did.status === "revoked"}
                onClick={() => act("revoked")}>Ký và thu hồi DID</button>
            </div>
            <p className="text-sm text-muted max-w-prose">
              Thu hồi là vĩnh viễn và thu hồi luôn quyền quản trị viên hoặc đơn vị cấp bằng của địa chỉ
              này, đưa địa chỉ về vai trò người học. Văn bằng đã cấp không tự mất hiệu lực; nếu có gian
              lận, thu hồi riêng ở tab Văn bằng. DID do chính chủ tự khoá thì quản trị viên không mở
              thay được; quản trị viên khoá đè lên thì chủ không tự mở được nữa.
            </p>
            <TxProgress tx={tx} okTitle={OK_TITLE[lastStatus]} />
          </div>
        </SignSheet>
      )}
    </Section>
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
    <Section title="Tra cứu tài liệu DID"
      description="Xem bản ghi DID và kiểm tra nội dung có còn khớp bản neo trên chuỗi không.">
      <form className="flex flex-col sm:flex-row gap-3 sm:items-end"
        onSubmit={(e) => { e.preventDefault(); resolve.mutate(); }}>
        <div className="flex-1">
          <Field label="DID" value={did} onChange={setDid} mono required
            placeholder="did:vnu:holder:0x…" />
        </div>
        <button className="btn-secondary sm:w-36" type="submit" disabled={resolve.isPending}>
          {resolve.isPending ? "Đang tra…" : "Tra cứu"}
        </button>
      </form>

      <div role="status" aria-live="polite">
        {err && <div className="mt-4"><Alert tone="bad" title="Không tra cứu được">{err}</Alert></div>}

        {result && (
          <div className="sheet p-5 mt-5">
            <div className="flex flex-wrap items-center gap-4 mb-4">
              <Rosette seed={result.did} size={64} />
              <div className="min-w-0">
                <h3 className="text-base font-semibold">Tài liệu DID</h3>
                <Mono value={result.did} />
              </div>
            </div>
            <dl className="grid sm:grid-cols-2 gap-x-6 gap-y-3">
              <Row label="Trạng thái"><DidStatusBadge status={result.status} /></Row>
              <Row label="Phiên bản">{result.version}</Row>
              <Row label="Mã nội dung tài liệu (CID)"><Mono value={result.documentCid} /></Row>
              <Row label="Toàn vẹn nội dung">
                {result.integrityOk === null
                  ? <Badge tone="muted">Chưa kiểm được</Badge>
                  : result.integrityOk
                    ? <Badge tone="ok">Khớp bản neo</Badge>
                    : <Badge tone="bad">Nội dung đã bị sửa</Badge>}
              </Row>
              <Row label="Nguồn">{result.source === "chain" ? "Chuỗi" : "Chỉ mục cơ sở dữ liệu"}</Row>
            </dl>
          </div>
        )}
      </div>
    </Section>
  );
}

interface Migration { old_address: string; new_address: string; old_did: string; new_did: string; note: string; created_at: string }

/**
 * P4.2 — holder mất khoá: ghi nhận ví mới thay cho ví cũ SAU KHI đã xác minh danh
 * tính ngoài hệ thống (phòng đào tạo, giấy tờ). Không có giao dịch: đây là hồ sơ
 * hành chính, không phải quyền — mối nối hai ví là thông tin cá nhân nên chỉ nằm ở
 * CSDL và nhật ký kiểm toán, không lên chuỗi.
 *
 * Trình tự: khoá/thu hồi DID cũ (thẻ "Kiểm duyệt DID") → người dùng lập ví mới và
 * đăng ký DID → ghi nhận ở đây → đơn vị cấp bằng thấy ví mới ở bảng "Cấp lại".
 */
function MigrationCard() {
  const [oldAddress, setOld] = useState("");
  const [newAddress, setNew] = useState("");
  const [note, setNote] = useState("");
  const save = useMutation({
    mutationFn: () => api.post<Migration>("/admin/identity-migrations", {
      oldAddress: oldAddress.trim(), newAddress: newAddress.trim(), note: note.trim(),
    }),
  });
  const ok = (a: string) => /^0x[0-9a-fA-F]{64}$/.test(a.trim());
  return (
    <Card title="Ghi nhận chuyển ví (người học mất khoá)"
      subtitle="Chỉ làm sau khi đã khoá hoặc thu hồi DID của ví cũ và xác minh danh tính người học.">
      <form className="grid sm:grid-cols-2 gap-4" onSubmit={(e) => { e.preventDefault(); save.mutate(); }}>
        <Field label="Ví cũ" value={oldAddress} onChange={setOld} mono required placeholder="0x…"
          hint="DID của ví này phải đã bị khoá hoặc thu hồi." />
        <Field label="Ví mới" value={newAddress} onChange={setNew} mono required placeholder="0x…"
          hint="Ví mới phải đã đăng ký DID." />
        <div className="sm:col-span-2">
          <Field label="Hồ sơ xác minh (ghi vào nhật ký)" value={note} onChange={setNote} required
            placeholder="Đối chiếu CCCD tại phòng đào tạo ngày …" />
        </div>
        <div className="sm:col-span-2">
          <button className="btn-primary" type="submit"
            disabled={save.isPending || !ok(oldAddress) || !ok(newAddress) || note.trim().length < 2}>
            {save.isPending ? "Đang ghi…" : "Ghi nhận chuyển ví"}
          </button>
        </div>
      </form>
      <div role="status" aria-live="polite">
        {save.error && <div className="mt-4"><Alert tone="bad" title="Không ghi nhận được">{(save.error as Error).message}</Alert></div>}
        {save.data && (
          <div className="mt-4"><Alert tone="ok" title="Đã ghi nhận">
            Ví cũ <Mono value={save.data.old_did} /> chuyển sang ví mới <Mono value={save.data.new_did} />.
            Đơn vị cấp bằng giờ thấy ví mới khi bấm "Cấp lại" trên văn bằng của ví cũ.
          </Alert></div>
        )}
      </div>
    </Card>
  );
}
