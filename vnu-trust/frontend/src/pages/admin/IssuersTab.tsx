import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useWallet } from "../../hooks/useWallet";
import { useAuthorityRoot, useChainTx } from "../../hooks/useChain";
import { ENTRY, bytesArg, hashArg, u64Arg } from "../../lib/chain";
import { sha3_256Hex } from "../../lib/wallet";
import { VC_TYPES, VC_TYPE_DELEGATION } from "../../lib/constants";
import { Card, Alert, Mono, Badge, Spinner, Empty, Field } from "../../components/ui";
import TxProgress from "../../components/ChainTx";
import type { RoleRow } from "./OverviewTab";

/**
 * Phê duyệt và quản lý đơn vị cấp bằng.
 *
 * Quy tắc lấy thẳng từ `authority::approve_issuer`:
 *  - root và admin đang hoạt động đều phê duyệt được;
 *  - riêng **bit uỷ quyền** (`VC_TYPE_DELEGATION`) chỉ root mới cấp được;
 *  - địa chỉ được cấp phải có DID còn hoạt động và không đang là admin;
 *  - issuer từng bị thu hồi thì phê duyệt lại được, bản ghi cũ giữ làm vết kiểm toán.
 */
export default function IssuersTab() {
  const issuers = useQuery({
    queryKey: ["admin", "issuers"],
    queryFn: () => api.get<RoleRow[]>("/admin/issuers"),
  });

  return (
    <div className="space-y-6">
      <ApproveIssuerCard />
      <Card title="Đơn vị cấp bằng"
        subtitle="Trạng thái đọc trực tiếp từ hợp đồng, không phải từ vai trò khai trong ứng dụng.">
        {issuers.isLoading && <Spinner />}
        {!issuers.isLoading && !issuers.data?.length && <Empty title="Chưa có đơn vị nào" />}
        {!!issuers.data?.length && <IssuerTable rows={issuers.data} />}
      </Card>
    </div>
  );
}

function ApproveIssuerCard() {
  const { wallet } = useWallet();
  const root = useAuthorityRoot();
  const qc = useQueryClient();
  const tx = useChainTx();

  const [address, setAddress] = useState("");
  const [mask, setMask] = useState(1);
  const [expiresAt, setExpiresAt] = useState("");

  const isRoot = root.data?.callerIsRoot ?? false;
  const expiresUnix = expiresAt ? Math.floor(new Date(expiresAt).getTime() / 1000) : 0;

  const approve = () =>
    void tx.run({
      fn: ENTRY.approveIssuer,
      args: async () => {
        // Chứng thư uỷ quyền luôn được ghim, kể cả khi hợp đồng không bắt buộc.
        // `approve_issuer` đòi CID + hash 32 byte khi có dính uỷ quyền, và chấp
        // nhận hash rỗng khi không (F-01). Ghim trong mọi trường hợp cho một
        // đường mã duy nhất — đổi lại còn có bản ghi kiểm toán của chính lần
        // phê duyệt này, thay vì một trường rỗng không nói lên điều gì.
        const doc = {
          type: "VNUDelegationCredential",
          issuer: wallet?.did ?? "",
          issuerAddress: wallet?.address ?? "",
          subject: address.trim(),
          vcTypeMask: mask,
          expiresAt: expiresUnix,
          approvedAt: new Date().toISOString(),
        };
        const hash = sha3_256Hex(doc);
        const { cid } = await api.post<{ cid: string }>("/ipfs/pin", {
          json: doc,
          name: `delegation-${address.trim().slice(0, 10)}`,
        });
        return [
          address.trim(),
          u64Arg(mask),
          bytesArg(cid),
          hashArg(hash),
          u64Arg(expiresUnix),
        ];
      },
      index: async (out) => {
        const r = await api.post("/admin/authority/issuers", {
          address: address.trim(),
          vcTypeMask: mask,
          expiresAt: expiresUnix,
          txHash: out.hash,
        });
        setAddress("");
        qc.invalidateQueries({ queryKey: ["admin"] });
        return r;
      },
    });

  return (
    <Card title="Phê duyệt đơn vị cấp bằng"
      subtitle="Ví của bạn ký trực tiếp — không cần dán mã giao dịch.">
      <Alert tone="info" title="Điều kiện của hợp đồng">
        Địa chỉ được duyệt phải <strong>đã đăng ký DID và DID còn hoạt động</strong>, và{" "}
        <strong>không đang là admin</strong>. Bit “Chứng chỉ uỷ quyền” cho phép đơn vị đó cấp
        quyền tiếp cho đơn vị con — <strong>chỉ root</strong> cấp được bit này.
      </Alert>

      <form className="mt-4 space-y-4" onSubmit={(e) => { e.preventDefault(); approve(); }}>
        <Field label="Địa chỉ ví đơn vị" value={address} onChange={setAddress} mono required
          placeholder="0x…" />

        <div>
          <span className="label">Loại văn bằng được phép cấp</span>
          <div className="flex flex-wrap gap-x-5 gap-y-2 mt-1">
            {VC_TYPES.map((t) => {
              const locked = Boolean(t.rootOnly) && !isRoot;
              return (
                <label key={t.bit}
                  className={`flex items-center gap-2 text-sm ${locked ? "text-ink-300" : "text-ink-700"}`}
                  title={locked ? "Chỉ root mới cấp được bit uỷ quyền" : undefined}>
                  <input type="checkbox" disabled={locked} checked={(mask & t.bit) !== 0}
                    onChange={(e) => setMask((m) => (e.target.checked ? m | t.bit : m & ~t.bit))} />
                  {t.label}
                  {t.rootOnly && <span className="text-xs text-ink-400">(root)</span>}
                </label>
              );
            })}
          </div>
          <p className="text-xs text-ink-400 mt-1.5">
            mask hiện tại: <span className="mono">{mask}</span>
            {(mask & VC_TYPE_DELEGATION) !== 0 && " — có bit uỷ quyền"}
          </p>
        </div>

        <Field label="Hạn uỷ quyền (để trống = vĩnh viễn)" value={expiresAt} onChange={setExpiresAt}
          type="datetime-local"
          hint="Hợp đồng nhận giây Unix; 0 nghĩa là không hết hạn." />

        <button className="btn-primary" disabled={!address.trim() || mask === 0 || tx.busy}>
          {tx.busy ? tx.label : "Ký & phê duyệt issuer"}
        </button>
      </form>

      <div className="mt-4"><TxProgress tx={tx} okTitle="Đã phê duyệt đơn vị cấp bằng" /></div>
    </Card>
  );
}

/** Bảng issuer kèm ba thao tác đổi trạng thái, mỗi thao tác là một giao dịch tự ký. */
function IssuerTable({ rows }: { rows: RoleRow[] }) {
  const qc = useQueryClient();
  const tx = useChainTx();
  const [target, setTarget] = useState<RoleRow | null>(null);
  const [reason, setReason] = useState("");

  const change = (status: "suspended" | "active" | "revoked") => {
    if (!target) return;
    const fn =
      status === "suspended" ? ENTRY.suspendIssuer
        : status === "active" ? ENTRY.reactivateIssuer
          : ENTRY.revokeIssuer;
    void tx.run({
      fn,
      args: [target.address, bytesArg(reason.trim())],
      index: async (out) => {
        const r = await api.post(
          `/admin/authority/issuers/${encodeURIComponent(target.address)}/status`,
          { status, reason: reason.trim(), txHash: out.hash },
        );
        setTarget(null); setReason("");
        qc.invalidateQueries({ queryKey: ["admin"] });
        return r;
      },
    });
  };

  return (
    <>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-left text-xs uppercase tracking-wide text-ink-400">
            <tr><th className="py-2">Tên</th><th>DID</th><th>Trên chuỗi</th><th></th></tr>
          </thead>
          <tbody className="divide-y divide-ink-100">
            {rows.map((r) => (
              <tr key={r.address}>
                <td className="py-2.5 font-medium text-ink-800">{r.label}</td>
                <td><Mono value={r.did} /></td>
                <td>{r.activeOnChain
                  ? <Badge tone="ok">Đang hoạt động</Badge>
                  : <Badge tone="bad">Chưa/không còn quyền</Badge>}</td>
                <td className="text-right">
                  <button type="button" className="btn-ghost !px-3 !py-1.5 text-xs"
                    onClick={() => { setTarget(r); setReason(""); tx.reset(); }}>
                    Đổi trạng thái
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {target && (
        <div className="mt-5 rounded-xl border border-ink-200 bg-ink-50/60 p-4 space-y-4">
          <p className="text-sm text-ink-700">
            Đổi trạng thái của <strong>{target.label}</strong> — <Mono value={target.address} />
          </p>
          <Field label="Lý do (ghi vào nhật ký kiểm toán)" value={reason} onChange={setReason}
            placeholder="Tạm ngưng do rà soát hồ sơ" />
          <div className="flex flex-wrap gap-3">
            <button className="btn-ghost" type="button"
              disabled={reason.trim().length < 2 || tx.busy}
              onClick={() => change("suspended")}>Tạm ngưng</button>
            <button className="btn-ghost" type="button"
              disabled={reason.trim().length < 2 || tx.busy}
              onClick={() => change("active")}>Kích hoạt lại</button>
            <button className="btn-danger" type="button"
              disabled={reason.trim().length < 2 || tx.busy}
              onClick={() => change("revoked")}>Thu hồi quyền</button>
            <button className="btn-ghost !text-ink-500" type="button"
              onClick={() => { setTarget(null); setReason(""); }}>Đóng</button>
          </div>
          <p className="text-xs text-ink-400">
            Thu hồi là vĩnh viễn với bản ghi hiện tại, nhưng địa chỉ vẫn được phê duyệt lại sau
            này (F-04) — bản ghi cũ ở lại trong hợp đồng làm vết kiểm toán.
          </p>
        </div>
      )}

      <div className="mt-4"><TxProgress tx={tx} okTitle="Đã đổi trạng thái issuer" /></div>
    </>
  );
}
