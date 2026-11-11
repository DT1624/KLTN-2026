import { useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { useWallet } from "../hooks/useWallet";
import { useMe, useAuthorityRoot, useChainTx } from "../hooks/useChain";
import { ENTRY } from "../lib/chain";
import { api } from "../lib/api";
import { Card, Alert, Mono, Badge, RoleBadge, Spinner } from "../components/ui";
import DidCard from "../components/DidCard";
import GasPanel from "../components/GasPanel";
import TxProgress from "../components/ChainTx";

/**
 * Trang "Danh tính & Gas" — nơi mọi tài khoản chuẩn bị để hoạt động được.
 *
 * Hai thứ một tài khoản mới cần trước khi làm bất cứ việc gì: **gas** để trả
 * phí giao dịch, và **DID** vì hợp đồng đòi DID đang hoạt động ở hầu hết các
 * hàm. Gom cả hai về một chỗ để không ai phải đoán vì sao nút của mình báo lỗi.
 */
export default function Account() {
  const { wallet } = useWallet();
  const me = useMe();
  const root = useAuthorityRoot();

  if (!wallet) return <Alert tone="warn" title="Chưa mở ví">Hãy mở ví để xem trang này.</Alert>;
  if (me.isLoading) return <Spinner label="Đang đọc hồ sơ…" />;

  const on = me.data?.onChain;
  const serverRole = me.data?.entity.role ?? wallet.role;

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-2xl font-bold text-ink-900">Danh tính &amp; gas</h1>
        <p className="text-sm text-ink-600 mt-1">
          Chuẩn bị tài khoản: nhận gas, đăng ký DID, xem quyền thật của mình trên chuỗi.
        </p>
      </header>

      <Card title="Tài khoản">
        <div className="flex flex-wrap items-center gap-3">
          <span className="font-semibold text-ink-900">{me.data?.entity.label ?? wallet.label}</span>
          <RoleBadge role={serverRole} />
          <Mono value={wallet.address} />
        </div>

        <div className="mt-4">
          <p className="text-xs font-semibold uppercase tracking-wide text-ink-500 mb-1.5">
            Quyền thật trên chuỗi
          </p>
          <div className="flex flex-wrap gap-2">
            <Badge tone={on?.hasActiveDid ? "ok" : "warn"}>
              {on?.hasActiveDid ? "DID đang hoạt động" : "Chưa có DID hoạt động"}
            </Badge>
            <Badge tone={on?.isActiveIssuer ? "ok" : "muted"}>
              {on?.isActiveIssuer ? "Issuer đang hoạt động" : "Không phải issuer"}
            </Badge>
            <Badge tone={on?.isActiveAdmin ? "ok" : "muted"}>
              {on?.isActiveAdmin ? "Admin đang hoạt động" : "Không phải admin"}
            </Badge>
            {on?.canDelegate && <Badge tone="info">Được uỷ quyền lại</Badge>}
            {root.data?.callerIsRoot && <Badge tone="info">Quản trị gốc</Badge>}
          </div>

          {me.data && !me.data.consistent && (
            <div className="mt-3">
              <Alert tone="warn" title="Vai trò khai trong ứng dụng chưa khớp quyền trên chuỗi">
                Hồ sơ ghi vai trò <strong>{serverRole}</strong> nhưng chuỗi chưa công nhận quyền
                tương ứng. Nút bấm trong khu vực đó sẽ bị hợp đồng từ chối cho tới khi quyền được
                cấp thật.
              </Alert>
            </div>
          )}
        </div>
      </Card>

      <DidCard />
      <GasPanel />

      {root.data?.callerIsPendingRoot && <AcceptRootCard />}

      <Card title="Khu vực làm việc">
        <div className="flex flex-wrap gap-3">
          <Link className="btn-ghost" to="/holder">Văn bằng của tôi</Link>
          {(on?.isActiveIssuer || serverRole === "issuer") && (
            <Link className="btn-ghost" to="/issuer">Cấp văn bằng</Link>
          )}
          {(on?.isActiveAdmin || serverRole === "admin" || serverRole === "root") && (
            <Link className="btn-ghost" to="/admin">Quản trị</Link>
          )}
          {root.data?.callerIsRoot && <Link className="btn-primary" to="/root">Quản trị gốc</Link>}
        </div>
      </Card>
    </div>
  );
}

/**
 * Bước 2 của chuyển quyền root: người được đề cử TỰ KÝ để nhận.
 *
 * Thẻ này cố tình nằm ở trang cá nhân chứ không nằm trong khu quản trị: lúc ký
 * nhận, người đó vẫn **chưa** phải root, nên không vào được màn hình root.
 * Chính chữ ký này mới là bằng chứng họ giữ khoá riêng — thứ mà kiểu chuyển
 * quyền một bước ngày trước không bao giờ chứng minh được (F-00).
 */
function AcceptRootCard() {
  const qc = useQueryClient();
  const tx = useChainTx();

  return (
    <Card title="Bạn đang được đề cử làm quản trị gốc"
      subtitle="Quyền root chỉ thật sự chuyển sang khi chính bạn ký nhận.">
      <Alert tone="warn" title="Đọc kỹ trước khi nhận">
        Nhận quyền root nghĩa là bạn chịu trách nhiệm cấp và thu hồi toàn bộ quyền admin, issuer
        của hệ thống. Root cũ sẽ mất quyền ngay khi giao dịch này thành công.
      </Alert>

      <button className="btn-danger mt-4" type="button" disabled={tx.busy}
        onClick={() => void tx.run({
          fn: ENTRY.acceptRoot,
          args: [],
          index: async (out) => {
            const r = await api.post("/authority/root/accept", { txHash: out.hash });
            qc.invalidateQueries();
            return r;
          },
        })}>
        {tx.busy ? tx.label : "Ký nhận quyền quản trị gốc"}
      </button>

      <div className="mt-4"><TxProgress tx={tx} okTitle="Đã nhận quyền quản trị gốc" /></div>
    </Card>
  );
}
