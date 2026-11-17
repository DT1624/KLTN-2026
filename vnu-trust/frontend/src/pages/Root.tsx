import { useState } from "react";
import type { ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { useWallet } from "../hooks/useWallet";
import { useAuthorityRoot, useChainTx } from "../hooks/useChain";
import { useTitle } from "../hooks/useTitle";
import { ENTRY, bytesArg } from "../lib/chain";
import { Section, Alert, Mono, Spinner, Empty, Field, Row, RoleStatusBadge } from "../components/ui";
import TxProgress, { SignSheet } from "../components/ChainTx";
import GasPanel from "../components/GasPanel";
import Rosette from "../components/Rosette";

interface RoleRow {
  address: string;
  did: string;
  label: string;
  createdAt: string;
  activeOnChain: boolean;
}

function PageHead({ children }: { children?: ReactNode }) {
  return (
    <header>
      <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">Quản trị gốc</h1>
      {children}
    </header>
  );
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
  useTitle("Quản trị gốc");
  const { wallet } = useWallet();
  const root = useAuthorityRoot();

  if (root.isLoading) {
    return (
      <div className="space-y-6">
        <PageHead />
        <Spinner label="Đang đọc quyền gốc…" />
      </div>
    );
  }

  if (!root.data?.callerIsRoot) {
    return (
      <div className="space-y-6">
        <PageHead />
        <Alert tone="bad" title="Trang này chỉ dành cho quản trị gốc">
          Ví đang mở không phải quản trị gốc trên chuỗi.
          {root.data?.rootAdmin && (
            <p className="mt-2">Quản trị gốc hiện tại: <Mono value={root.data.rootAdmin} /></p>
          )}
        </Alert>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHead>
        <p className="text-muted max-w-prose mt-2">
          Cấp và thu hồi quyền quản trị viên, chuyển quyền gốc. Mọi thao tác ở đây do chính ví của
          bạn ký.
        </p>
      </PageHead>

      <Section title="Quyền gốc hiện tại">
        <div className="flex flex-wrap items-start gap-5">
          {root.data.rootAdmin && <Rosette seed={root.data.rootAdmin} size={64} />}
          <dl className="grid sm:grid-cols-2 gap-x-6 gap-y-3 flex-1 min-w-0">
            <Row label="Quản trị gốc trên chuỗi">
              {root.data.rootAdmin ? <Mono value={root.data.rootAdmin} truncate={false} /> : "Chưa có"}
            </Row>
            <Row label="Ví đang dùng">
              <Mono value={wallet?.address ?? ""} truncate={false} />
            </Row>
            <Row label="Đang đề cử">
              {root.data.pendingRoot
                ? <Mono value={root.data.pendingRoot} truncate={false} />
                : <span className="text-muted">Không có</span>}
            </Row>
            <Row label="Nguồn dữ liệu">
              {root.data.source === "chain" ? "Đọc trực tiếp từ chuỗi" : "Chỉ mục cơ sở dữ liệu"}
            </Row>
          </dl>
        </div>
      </Section>

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
    <Section title="Cấp quyền quản trị viên"
      description="Quản trị viên phê duyệt được đơn vị cấp bằng và xử lý sự cố văn bằng, nhưng không cấp được quản trị viên khác.">
      <SignSheet tx={tx}>
        <div className="space-y-4">
          <Alert tone="info" title="Điều kiện">
            Địa chỉ được cấp phải <strong>đã đăng ký DID và DID còn hoạt động</strong>, và{" "}
            <strong>không đang là đơn vị cấp bằng</strong>. Một địa chỉ không thể vừa là quản trị
            viên vừa là đơn vị cấp bằng. Quản trị viên từng bị thu hồi thì cấp lại được, bản ghi cũ
            vẫn ở lại làm vết kiểm toán.
          </Alert>

          <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); submit(); }}>
            <Field label="Địa chỉ ví" value={address} onChange={setAddress} mono required
              placeholder="0x…" />
            <button className="btn-primary" disabled={!address.trim() || tx.busy}>
              Ký và cấp quyền quản trị viên
            </button>
          </form>

          <TxProgress tx={tx} okTitle="Đã cấp quyền quản trị viên" />
        </div>
      </SignSheet>
    </Section>
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
    <Section title="Quản trị viên hiện có"
      description="Thu hồi quyền có hiệu lực ngay trên chuỗi; bản ghi cũ vẫn giữ để truy vết.">
      {admins.isLoading && <Spinner />}
      {!admins.isLoading && !admins.data?.length && (
        <Empty title="Chưa có quản trị viên nào"
          hint="Cấp quyền cho quản trị viên đầu tiên bằng biểu mẫu ở trên." />
      )}

      {!!admins.data?.length && (
        <div className="overflow-x-auto">
          <table className="table">
            <thead>
              <tr><th>Tên</th><th>Địa chỉ</th><th>Trên chuỗi</th><th></th></tr>
            </thead>
            <tbody>
              {admins.data.map((r) => (
                <tr key={r.address}>
                  <td className="font-semibold">{r.label}</td>
                  <td><Mono value={r.address} /></td>
                  <td>{r.activeOnChain
                    ? <RoleStatusBadge status="active" />
                    : <RoleStatusBadge status="revoked" />}</td>
                  <td className="text-right">
                    {r.activeOnChain && (
                      <button type="button" className="btn-quiet text-son"
                        onClick={() => setTarget(r.address)}>
                        Thu hồi quyền
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {(target || tx.step !== "idle") && (
        <SignSheet tx={tx} className="mt-5">
          <div className="space-y-4">
            {target && (
              <>
                <p>Thu hồi quyền quản trị viên của <Mono value={target} /></p>
                <Field label="Lý do (ghi vào nhật ký kiểm toán)" value={reason} onChange={setReason}
                  placeholder="Hết nhiệm kỳ" />
                <div className="flex flex-wrap gap-3">
                  <button className="btn-danger" type="button"
                    disabled={reason.trim().length < 2 || tx.busy}
                    onClick={revoke}>
                    Ký và thu hồi quyền quản trị viên
                  </button>
                  <button className="btn-secondary" type="button"
                    onClick={() => { setTarget(""); setReason(""); tx.reset(); }}>Huỷ</button>
                </div>
              </>
            )}
            <TxProgress tx={tx} okTitle="Đã thu hồi quyền quản trị viên" />
          </div>
        </SignSheet>
      )}
    </Section>
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
    <Section title="Chuyển quyền quản trị gốc"
      description="Quyền chưa đổi cho tới khi người được đề cử tự ký nhận.">
      <SignSheet tx={proposeTx.step !== "idle" ? proposeTx : cancelTx}>
        <div className="space-y-4">
          <ol className="max-w-prose space-y-2">
            <li className="flex items-center gap-3">
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary-soft text-primary text-sm font-semibold" aria-hidden="true">1</span>
              <span>Bạn đề cử địa chỉ mới và ký.</span>
            </li>
            <li className="flex items-center gap-3">
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary-soft text-primary text-sm font-semibold" aria-hidden="true">2</span>
              <span>Người được đề cử tự ký nhận ở trang Tài khoản của họ.</span>
            </li>
          </ol>

          {pendingRoot ? (
            <Alert tone="warn" title="Đang có đề cử chờ ký nhận">
              <Mono value={pendingRoot} truncate={false} />
              <p className="mt-2">
                Bạn <strong>vẫn là quản trị gốc</strong> cho tới khi chính địa chỉ này ký nhận. Đổi ý
                thì huỷ đề cử bên dưới.
              </p>
            </Alert>
          ) : (
            <p className="text-muted">Không có đề cử nào đang chờ.</p>
          )}

          <form className="space-y-4" onSubmit={(e) => { e.preventDefault(); propose(); }}>
            <Field label="Địa chỉ được đề cử" value={address} onChange={setAddress} mono
              placeholder="0x…"
              hint="Nên là địa chỉ đã đăng ký trong hệ thống và bạn chắc chắn có người giữ khoá." />
            <div className="flex flex-wrap gap-3">
              <button className="btn-danger" disabled={!address.trim() || proposeTx.busy}>
                Ký và đề cử quản trị gốc mới
              </button>
              {pendingRoot && (
                <button className="btn-secondary" type="button" disabled={cancelTx.busy} onClick={cancel}>
                  Ký và huỷ đề cử
                </button>
              )}
            </div>
          </form>

          <div className="space-y-3">
            <TxProgress tx={proposeTx} okTitle="Đã đề cử quản trị gốc mới" />
            <TxProgress tx={cancelTx} okTitle="Đã huỷ đề cử" />
          </div>
        </div>
      </SignSheet>
    </Section>
  );
}
