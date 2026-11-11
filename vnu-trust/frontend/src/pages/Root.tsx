import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useWallet } from "../hooks/useWallet";
import { useAuthorityRoot, useChainTx } from "../hooks/useChain";
import { ENTRY, bytesArg } from "../lib/chain";
import { Card, Alert, Mono, Badge, Spinner, Empty, Field, Row } from "../components/ui";
import TxProgress from "../components/ChainTx";
import GasPanel from "../components/GasPanel";

interface RoleRow {
  address: string;
  did: string;
  label: string;
  createdAt: string;
  activeOnChain: boolean;
}

/**
 * MÀN HÌNH QUẢN TRỊ GỐC.
 *
 * Chỉ ba việc, nhưng là ba việc không ai khác làm được — hợp đồng kiểm
 * `signer::address_of(root) == authority.root_admin` ngay dòng đầu của
 * `grant_admin`, `revoke_admin`, `propose_root` và `cancel_root_transfer`.
 *
 * Tách khỏi màn hình quản trị viên vì nhầm lẫn ở đây tốn kém nhất: cấp quyền
 * admin cho nhầm địa chỉ còn gỡ được, chứ đề cử root cho một địa chỉ không ai
 * giữ khoá thì người nhận không bao giờ ký nhận được — may là chuyển quyền hai
 * bước nên vẫn huỷ được đề cử (F-00).
 */
export default function Root() {
  const { wallet } = useWallet();
  const root = useAuthorityRoot();

  if (root.isLoading) return <Spinner label="Đang đọc quyền gốc…" />;

  if (!root.data?.callerIsRoot) {
    return (
      <Alert tone="bad" title="Trang này chỉ dành cho quản trị gốc">
        Địa chỉ đang đăng nhập không phải <span className="mono">root_admin</span> trên chuỗi.
        {root.data?.rootAdmin && (
          <p className="mt-2">Root hiện tại: <Mono value={root.data.rootAdmin} /></p>
        )}
      </Alert>
    );
  }

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold text-ink-900">Quản trị gốc</h1>
        <p className="text-sm text-ink-600 mt-1">
          Cấp và thu hồi quyền quản trị viên, chuyển quyền gốc. Mọi thao tác ở đây do chính ví của
          bạn ký.
        </p>
      </header>

      <Card title="Quyền gốc hiện tại">
        <dl className="grid sm:grid-cols-2 gap-x-6 gap-y-3 text-sm">
          <Row label="Root trên chuỗi">
            {root.data.rootAdmin ? <Mono value={root.data.rootAdmin} truncate={false} /> : "—"}
          </Row>
          <Row label="Ví đang dùng">
            <Mono value={wallet?.address ?? ""} truncate={false} />
          </Row>
          <Row label="Đang đề cử">
            {root.data.pendingRoot
              ? <Mono value={root.data.pendingRoot} truncate={false} />
              : <span className="text-ink-400">Không có</span>}
          </Row>
          <Row label="Nguồn dữ liệu">
            {root.data.source === "chain" ? "Đọc trực tiếp từ chuỗi" : "Chỉ mục CSDL"}
          </Row>
        </dl>
      </Card>

      <GasPanel />
      <GrantAdminCard />
      <AdminListCard />
      <RootTransferCard pendingRoot={root.data.pendingRoot} />
    </div>
  );
}

function GrantAdminCard() {
  const qc = useQueryClient();
  const tx = useChainTx();
  const [address, setAddress] = useState("");

  const submit = () =>
    void tx.run({
      fn: ENTRY.grantAdmin,
      args: [address.trim()],
      index: async (out) => {
        const r = await api.post("/admin/authority/admins", {
          address: address.trim(),
          txHash: out.hash,
        });
        setAddress("");
        qc.invalidateQueries({ queryKey: ["admin"] });
        return r;
      },
    });

  return (
    <Card title="Cấp quyền quản trị viên"
      subtitle="Admin phê duyệt được issuer và xử lý sự cố văn bằng, nhưng không cấp được admin khác.">
      <Alert tone="info" title="Điều kiện của hợp đồng">
        Địa chỉ được cấp phải <strong>đã đăng ký DID và DID còn hoạt động</strong>, và{" "}
        <strong>không đang là issuer</strong> — một địa chỉ không thể vừa admin vừa issuer (F-11d).
        Admin từng bị thu hồi thì cấp lại được, bản ghi cũ vẫn ở lại làm vết kiểm toán.
      </Alert>

      <form className="mt-4 space-y-4" onSubmit={(e) => { e.preventDefault(); submit(); }}>
        <Field label="Địa chỉ ví" value={address} onChange={setAddress} mono required
          placeholder="0x…" />
        <button className="btn-primary" disabled={!address.trim() || tx.busy}>
          {tx.busy ? tx.label : "Ký & cấp quyền admin"}
        </button>
      </form>

      <div className="mt-4"><TxProgress tx={tx} okTitle="Đã cấp quyền quản trị viên" /></div>
    </Card>
  );
}

function AdminListCard() {
  const qc = useQueryClient();
  const tx = useChainTx();
  const [target, setTarget] = useState("");
  const [reason, setReason] = useState("");

  const admins = useQuery({
    queryKey: ["admin", "admins"],
    queryFn: () => api.get<RoleRow[]>("/admin/admins"),
  });

  const revoke = () =>
    void tx.run({
      fn: ENTRY.revokeAdmin,
      args: [target, bytesArg(reason.trim())],
      index: async (out) => {
        const r = await api.post(
          `/admin/authority/admins/${encodeURIComponent(target)}/revoke`,
          { reason: reason.trim(), txHash: out.hash },
        );
        setTarget(""); setReason("");
        qc.invalidateQueries({ queryKey: ["admin"] });
        return r;
      },
    });

  return (
    <Card title="Quản trị viên hiện có"
      subtitle="Thu hồi quyền có hiệu lực ngay trên chuỗi; bản ghi cũ vẫn giữ để truy vết.">
      {admins.isLoading && <Spinner />}
      {!admins.isLoading && !admins.data?.length && <Empty title="Chưa có quản trị viên nào" />}

      {!!admins.data?.length && (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-left text-xs uppercase tracking-wide text-ink-400">
              <tr><th className="py-2">Tên</th><th>Địa chỉ</th><th>Trên chuỗi</th><th></th></tr>
            </thead>
            <tbody className="divide-y divide-ink-100">
              {admins.data.map((r) => (
                <tr key={r.address}>
                  <td className="py-2.5 font-medium text-ink-800">{r.label}</td>
                  <td><Mono value={r.address} /></td>
                  <td>{r.activeOnChain
                    ? <Badge tone="ok">Đang hoạt động</Badge>
                    : <Badge tone="muted">Không còn quyền</Badge>}</td>
                  <td className="text-right">
                    {r.activeOnChain && (
                      <button type="button" className="btn-ghost !px-3 !py-1.5 text-xs !text-rose-600"
                        onClick={() => setTarget(r.address)}>
                        Chọn để thu hồi
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {target && (
        <div className="mt-5 rounded-xl border border-rose-200 bg-rose-50/50 p-4 space-y-4">
          <p className="text-sm text-ink-700">
            Thu hồi quyền admin của <Mono value={target} />
          </p>
          <Field label="Lý do (ghi vào nhật ký kiểm toán)" value={reason} onChange={setReason}
            placeholder="Hết nhiệm kỳ" />
          <div className="flex flex-wrap gap-3">
            <button className="btn-danger" type="button"
              disabled={reason.trim().length < 2 || tx.busy}
              onClick={revoke}>
              {tx.busy ? tx.label : "Ký & thu hồi quyền admin"}
            </button>
            <button className="btn-ghost" type="button"
              onClick={() => { setTarget(""); setReason(""); tx.reset(); }}>Huỷ</button>
          </div>
        </div>
      )}

      <div className="mt-4"><TxProgress tx={tx} okTitle="Đã thu hồi quyền admin" /></div>
    </Card>
  );
}

/**
 * Chuyển quyền gốc — HAI BƯỚC.
 *
 * Bước 1 ở đây (root đề cử). Bước 2 nằm ở trang "Danh tính & gas" của người
 * được đề cử, vì lúc ký nhận họ vẫn chưa phải root nên không vào được trang này.
 */
function RootTransferCard({ pendingRoot }: { pendingRoot: string | null }) {
  const qc = useQueryClient();
  const proposeTx = useChainTx();
  const cancelTx = useChainTx();
  const [address, setAddress] = useState("");

  const propose = () =>
    void proposeTx.run({
      fn: ENTRY.proposeRoot,
      args: [address.trim()],
      index: async (out) => {
        const r = await api.post("/admin/authority/root/propose", {
          address: address.trim(),
          txHash: out.hash,
        });
        setAddress("");
        qc.invalidateQueries({ queryKey: ["authority"] });
        return r;
      },
    });

  const cancel = () =>
    void cancelTx.run({
      fn: ENTRY.cancelRootTransfer,
      args: [],
      index: async (out) => {
        const r = await api.post("/admin/authority/root/cancel", { txHash: out.hash });
        qc.invalidateQueries({ queryKey: ["authority"] });
        return r;
      },
    });

  return (
    <Card title="Chuyển quyền quản trị gốc"
      subtitle="Root đề cử, người nhận tự ký chấp nhận. Quyền chưa đổi cho tới bước hai.">
      {pendingRoot ? (
        <Alert tone="warn" title="Đang có đề cử chờ ký nhận">
          <Mono value={pendingRoot} truncate={false} />
          <p className="mt-2">
            Bạn <strong>vẫn là root</strong> cho tới khi chính địa chỉ này ký nhận. Đổi ý thì huỷ
            đề cử bên dưới.
          </p>
        </Alert>
      ) : (
        <p className="text-sm text-ink-600">Không có đề cử nào đang chờ.</p>
      )}

      <form className="mt-4 space-y-4" onSubmit={(e) => { e.preventDefault(); propose(); }}>
        <Field label="Địa chỉ được đề cử" value={address} onChange={setAddress} mono
          placeholder="0x…"
          hint="Nên là địa chỉ đã đăng ký trong hệ thống và bạn chắc chắn có người giữ khoá." />
        <div className="flex flex-wrap gap-3">
          <button className="btn-primary" disabled={!address.trim() || proposeTx.busy}>
            {proposeTx.busy ? proposeTx.label : "Ký & đề cử root mới"}
          </button>
          {pendingRoot && (
            <button className="btn-ghost" type="button" disabled={cancelTx.busy} onClick={cancel}>
              {cancelTx.busy ? cancelTx.label : "Huỷ đề cử"}
            </button>
          )}
        </div>
      </form>

      <div className="mt-4 space-y-3">
        <TxProgress tx={proposeTx} okTitle="Đã đề cử root mới" />
        <TxProgress tx={cancelTx} okTitle="Đã huỷ đề cử" />
      </div>
    </Card>
  );
}
