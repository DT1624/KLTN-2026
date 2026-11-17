import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../../lib/api";
import { useAuthorityRoot, useMe } from "../../hooks/useChain";
import { Section, Ledger, Spinner, Mono, Badge, RoleStatusBadge, Empty, Alert } from "../../components/ui";
import GasPanel from "../../components/GasPanel";
import { StatusBar, MonthlyBars, BarList, ValidityMeter, type MonthPoint } from "../../components/charts";

interface Analytics {
  credentials: {
    active: number; suspended: number; expired: number; revoked: number; total: number;
    byMonth: MonthPoint[];
    byType: { vcType: number; label: string; count: number }[];
  };
  topIssuers: { did: string; label: string | null; count: number }[];
  verifications: { total: number; valid: number };
}

export interface Overview {
  onChain: { admins: number; issuers: number; rootAdmin: string | null };
  inApp: Record<string, number>;
  issuerDrift: number;
}

export interface RoleRow {
  address: string;
  did: string;
  label: string;
  createdAt: string;
  activeOnChain: boolean;
}

/** Tổng quan: số liệu trên chuỗi đối chiếu với chỉ mục ứng dụng, và tình trạng ví đang dùng. */
export default function OverviewTab() {
  const me = useMe();
  const root = useAuthorityRoot();
  const ov = useQuery({
    queryKey: ["admin", "overview"],
    queryFn: () => api.get<Overview>("/admin/overview"),
  });
  const stats = useQuery({
    queryKey: ["admin", "analytics"],
    queryFn: () => api.get<Analytics>("/admin/analytics"),
  });
  const admins = useQuery({
    queryKey: ["admin", "admins"],
    queryFn: () => api.get<RoleRow[]>("/admin/admins"),
  });

  if (ov.isLoading) return <Spinner label="Đang tải bảng điều khiển…" />;

  const on = me.data?.onChain;

  return (
    <div className="space-y-6">
      {on && !on.isActiveAdmin && !root.data?.callerIsRoot && (
        <Alert tone="bad" title="Ví này chưa có quyền quản trị viên trên chuỗi">
          Bạn xem được số liệu, nhưng mọi nút ký giao dịch ở các tab khác sẽ bị sổ đăng ký trên chuỗi
          từ chối. Ví này chưa được quản trị gốc cấp quyền quản trị viên trên chuỗi.
        </Alert>
      )}
      {on && !on.hasActiveDid && (
        <Alert tone="warn" title="Ví này chưa đăng ký DID">
          Mọi thao tác quản trị đều đòi DID còn hoạt động. Sang{" "}
          <Link className="link" to="/account">trang Danh tính và phí giao dịch</Link> để đăng ký trước.
        </Alert>
      )}

      {ov.data && (
        <div className="space-y-6">
          <Ledger items={[
            { label: "Quản trị viên trên chuỗi", value: ov.data.onChain.admins },
            { label: "Đơn vị cấp bằng trên chuỗi", value: ov.data.onChain.issuers },
            { label: "Đơn vị cấp bằng trong ứng dụng", value: ov.data.inApp.issuer ?? 0 },
            { label: "Người học", value: ov.data.inApp.holder ?? 0 },
          ]} />

          {ov.data.issuerDrift !== 0 && (
            <Alert tone="warn" title="Số liệu lệch nhau">
              Trên chuỗi có {ov.data.onChain.issuers} đơn vị cấp bằng nhưng ứng dụng mới ghi danh{" "}
              {ov.data.inApp.issuer ?? 0}. Chênh {ov.data.issuerDrift}. Thường do đơn vị được cấp
              quyền trực tiếp trên chuỗi mà chưa đăng ký trong ứng dụng.
            </Alert>
          )}
        </div>
      )}

      {stats.data && (
        <div className="grid lg:grid-cols-2 gap-4">
          <div className="sheet p-5 min-w-0">
            <h3 className="text-base font-semibold">Văn bằng cấp theo tháng</h3>
            <p className="text-sm text-muted mb-3">Tổng {stats.data.credentials.total} văn bằng trong hệ thống</p>
            <MonthlyBars data={stats.data.credentials.byMonth} />
          </div>
          <div className="sheet p-5 min-w-0">
            <h3 className="text-base font-semibold mb-3">Kết quả xác minh</h3>
            <ValidityMeter {...stats.data.verifications} />
          </div>
          <div className="sheet p-5 min-w-0">
            <h3 className="text-base font-semibold mb-3">Tình trạng văn bằng</h3>
            <StatusBar counts={stats.data.credentials} />
            <div className="mt-6">
              <BarList items={stats.data.credentials.byType.map((t) => ({ key: String(t.vcType), label: t.label, count: t.count }))} />
            </div>
          </div>
          <div className="sheet p-5 min-w-0">
            <h3 className="text-base font-semibold mb-3">Đơn vị cấp nhiều nhất</h3>
            <BarList empty="Chưa đơn vị nào cấp văn bằng."
              items={stats.data.topIssuers.map((i) => ({ key: i.did, label: i.label ?? i.did, count: i.count }))} />
          </div>
        </div>
      )}

      <Section title="Quản trị gốc"
        description="Địa chỉ giữ quyền cao nhất. Chỉ địa chỉ này cấp và thu hồi được quyền quản trị viên.">
        {root.data?.rootAdmin
          ? <Mono value={root.data.rootAdmin} truncate={false} />
          : <p className="text-sm text-muted">Không đọc được (chế độ không nối chuỗi)</p>}
        {root.data?.pendingRoot && (
          <div className="mt-3">
            <Alert tone="warn" title="Đang có đề cử chuyển quyền gốc">
              <Mono value={root.data.pendingRoot} truncate={false} />
              <p className="mt-1">Quyền chưa đổi cho tới khi chính địa chỉ đó ký nhận.</p>
            </Alert>
          </div>
        )}
        {root.data?.callerIsRoot && (
          <div className="mt-4">
            <Link className="btn-secondary" to="/root">Mở trang quản trị gốc</Link>
          </div>
        )}
      </Section>

      <GasPanel />

      <Section title="Quản trị viên"
        description="Cấp và thu hồi quyền quản trị viên là việc của quản trị gốc, ở trang quản trị gốc.">
        {admins.isLoading && <Spinner />}
        {!admins.isLoading && !admins.data?.length && <Empty title="Chưa có quản trị viên nào" />}
        {!!admins.data?.length && (
          <div className="overflow-x-auto">
            <table className="table">
              <thead>
                <tr><th>Tên</th><th>DID</th><th>Ghi danh</th><th>Trên chuỗi</th></tr>
              </thead>
              <tbody>
                {admins.data.map((r) => (
                  <tr key={r.address}>
                    <td>{r.label}</td>
                    <td><Mono value={r.did} /></td>
                    <td>{new Date(r.createdAt).toLocaleDateString("vi-VN")}</td>
                    <td>{r.activeOnChain
                      ? <RoleStatusBadge status="active" />
                      : <Badge tone="bad">Chưa có hoặc đã mất quyền</Badge>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </div>
  );
}
