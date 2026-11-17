import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../lib/api";
import { useWallet } from "../../hooks/useWallet";
import { useAuthorityRoot, useChainTx } from "../../hooks/useChain";
import { ENTRY, bytesArg, hashArg, u64Arg } from "../../lib/chain";
import { sha3_256Hex } from "../../lib/wallet";
import { VC_TYPES, maskLabel } from "../../lib/constants";
import { Section, Alert, Mono, Badge, RoleStatusBadge, Spinner, Empty, Field } from "../../components/ui";
import TxProgress, { SignSheet } from "../../components/ChainTx";
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
      <Section title="Đơn vị cấp bằng"
        description="Trạng thái đọc trực tiếp từ chuỗi, không phải từ vai trò khai trong ứng dụng.">
        {issuers.isLoading && <Spinner />}
        {!issuers.isLoading && !issuers.data?.length && (
          <Empty title="Chưa có đơn vị cấp bằng nào"
            hint="Phê duyệt đơn vị đầu tiên bằng biểu mẫu ở trên." />
        )}
        {!!issuers.data?.length && <IssuerTable rows={issuers.data} />}
      </Section>
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
    <Section title="Phê duyệt đơn vị cấp bằng"
      description="Ví của bạn ký trực tiếp giao dịch phê duyệt.">
      <div className="mb-4">
        <Alert tone="info" title="Điều kiện phê duyệt">
          Địa chỉ được duyệt phải <strong>đã đăng ký DID và DID còn hoạt động</strong>, và{" "}
          <strong>không đang là quản trị viên</strong>. Quyền “Chứng chỉ uỷ quyền” cho phép đơn vị
          đó cấp quyền tiếp cho đơn vị con, và <strong>chỉ quản trị gốc</strong> giao được quyền này.
        </Alert>
      </div>

      <SignSheet tx={tx}>
        <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); approve(); }}>
          <Field label="Địa chỉ ví đơn vị" value={address} onChange={setAddress} mono required
            placeholder="0x…" />

          <fieldset>
            <legend className="label">Loại văn bằng được cấp</legend>
            <ul className="mt-1 space-y-2">
              {VC_TYPES.map((t) => {
                const locked = Boolean(t.rootOnly) && !isRoot;
                return (
                  <li key={t.bit}>
                    <label className={`flex items-center gap-2 min-h-[44px] ${locked ? "text-muted" : ""}`}>
                      <input type="checkbox" disabled={locked} checked={(mask & t.bit) !== 0}
                        onChange={(e) => setMask((m) => (e.target.checked ? m | t.bit : m & ~t.bit))} />
                      {t.label}
                      {t.rootOnly && <span className="text-sm text-muted">(chỉ quản trị gốc)</span>}
                    </label>
                    {locked && (
                      <p className="text-sm text-muted ml-6">
                        Chỉ quản trị gốc mới giao được quyền uỷ quyền lại.
                      </p>
                    )}
                  </li>
                );
              })}
            </ul>
            <p className="text-sm text-muted mt-2">
              Quyền hiện tại: {mask === 0 ? "chưa chọn loại nào" : maskLabel(mask)}
            </p>
          </fieldset>

          <Field label="Hạn uỷ quyền (để trống nếu không hết hạn)" value={expiresAt} onChange={setExpiresAt}
            type="datetime-local"
            hint="Để trống nếu quyền không có ngày hết hạn." />

          <button className="btn-primary" disabled={!address.trim() || mask === 0 || tx.busy}>
            {tx.busy ? tx.label : "Ký và phê duyệt"}
          </button>
        </form>

        <div className="mt-4"><TxProgress tx={tx} okTitle="Đã phê duyệt đơn vị cấp bằng" /></div>
      </SignSheet>
    </Section>
  );
}

type IssuerStatus = "suspended" | "active" | "revoked";

function okTitle(s: IssuerStatus): string {
  if (s === "suspended") return "Đã tạm ngưng đơn vị";
  if (s === "active") return "Đã kích hoạt lại đơn vị";
  return "Đã thu hồi quyền đơn vị";
}

/** Bảng issuer kèm ba thao tác đổi trạng thái, mỗi thao tác là một giao dịch tự ký. */
function IssuerTable({ rows }: { rows: RoleRow[] }) {
  const qc = useQueryClient();
  const tx = useChainTx();
  const [target, setTarget] = useState<RoleRow | null>(null);
  const [reason, setReason] = useState("");
  const [lastStatus, setLastStatus] = useState<IssuerStatus>("suspended");

  const change = (status: IssuerStatus) => {
    if (!target) return;
    setLastStatus(status);
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
        <table className="table">
          <thead>
            <tr><th>Tên</th><th>DID</th><th>Trên chuỗi</th><th><span className="sr-only">Thao tác</span></th></tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.address}>
                <td>{r.label}</td>
                <td><Mono value={r.did} /></td>
                <td>{r.activeOnChain
                  ? <RoleStatusBadge status="active" />
                  : <Badge tone="bad">Chưa có hoặc đã mất quyền</Badge>}</td>
                <td className="text-right">
                  <button type="button" className="btn-secondary"
                    aria-label={`Đổi trạng thái của ${r.label}`}
                    onClick={() => { setTarget(r); setReason(""); tx.reset(); }}>
                    Đổi trạng thái
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {target ? (
        <div className="mt-5">
          <SignSheet tx={tx}>
            <div className="space-y-4">
              <div>
                <p>Đổi trạng thái của <strong>{target.label}</strong></p>
                <Mono value={target.address} />
              </div>
              <Field label="Lý do (ghi vào nhật ký kiểm toán)" value={reason} onChange={setReason}
                placeholder="Tạm ngưng do rà soát hồ sơ" />
              <div className="flex flex-wrap gap-3">
                <button className="btn-secondary" type="button"
                  disabled={reason.trim().length < 2 || tx.busy}
                  onClick={() => change("suspended")}>Ký và tạm ngưng</button>
                <button className="btn-primary" type="button"
                  disabled={reason.trim().length < 2 || tx.busy}
                  onClick={() => change("active")}>Ký và kích hoạt lại</button>
                <button className="btn-danger" type="button"
                  disabled={reason.trim().length < 2 || tx.busy}
                  onClick={() => change("revoked")}>Ký và thu hồi quyền</button>
                <button className="btn-quiet" type="button"
                  onClick={() => { setTarget(null); setReason(""); }}>Đóng</button>
              </div>
              <p className="text-sm text-muted">
                Thu hồi là vĩnh viễn với bản ghi hiện tại, nhưng địa chỉ vẫn được phê duyệt lại sau
                này. Bản ghi cũ ở lại trên chuỗi làm vết kiểm toán.
              </p>
            </div>
            <div className="mt-4"><TxProgress tx={tx} okTitle={okTitle(lastStatus)} /></div>
          </SignSheet>
        </div>
      ) : (
        <div className="mt-4"><TxProgress tx={tx} okTitle={okTitle(lastStatus)} /></div>
      )}
    </>
  );
}
