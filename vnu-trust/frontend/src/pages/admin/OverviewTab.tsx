import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../../lib/api";
import { useAuthorityRoot, useMe } from "../../hooks/useChain";
import { Card, Stat, Spinner, Mono, Badge, Empty, Alert } from "../../components/ui";
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
        <Alert tone="bad" title="Ví này chưa có quyền admin trên chuỗi">
          Bạn xem được số liệu, nhưng mọi nút ký giao dịch ở các tab khác sẽ bị hợp đồng từ chối.
          Quyền admin do <span className="mono">authority::grant_admin</span> cấp và chỉ root gọi
          được hàm đó.
        </Alert>
      )}
      {on && !on.hasActiveDid && (
        <Alert tone="warn" title="Ví này chưa đăng ký DID">
          Hợp đồng đòi DID còn hoạt động ở mọi hàm quản trị. Sang{" "}
          <Link className="underline" to="/account">Danh tính &amp; gas</Link> để đăng ký trước.
        </Alert>
      )}

      {ov.data && (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <Stat label="Admin trên chuỗi" value={ov.data.onChain.admins} />
            <Stat label="Issuer trên chuỗi" value={ov.data.onChain.issuers} />
            <Stat label="Issuer trong ứng dụng" value={ov.data.inApp.issuer ?? 0} />
            <Stat label="Người sở hữu" value={ov.data.inApp.holder ?? 0} />
          </div>

          {ov.data.issuerDrift !== 0 && (
            <Alert tone="warn" title="Số liệu lệch nhau">
              Trên chuỗi có {ov.data.onChain.issuers} issuer nhưng ứng dụng mới ghi danh{" "}
              {ov.data.inApp.issuer ?? 0}. Chênh {ov.data.issuerDrift}. Thường do issuer được cấp
              quyền trực tiếp on-chain mà chưa đăng ký trong ứng dụng.
            </Alert>
          )}
        </>
      )}

      {stats.data && (
        <div className="grid lg:grid-cols-3 gap-4">
          <Card title="Văn bằng cấp theo tháng" subtitle={`Tổng ${stats.data.credentials.total} văn bằng trong hệ thống`}
            className="lg:col-span-2">
            <MonthlyBars data={stats.data.credentials.byMonth} />
          </Card>
          <Card title="Kết quả xác minh">
            <ValidityMeter {...stats.data.verifications} />
          </Card>
          <Card title="Tình trạng văn bằng" className="lg:col-span-2">
            <StatusBar counts={stats.data.credentials} />
            <div className="mt-6">
              <BarList items={stats.data.credentials.byType.map((t) => ({ key: String(t.vcType), label: t.label, count: t.count }))} />
            </div>
          </Card>
          <Card title="Đơn vị cấp nhiều nhất">
            <BarList empty="Chưa đơn vị nào cấp văn bằng."
              items={stats.data.topIssuers.map((i) => ({ key: i.did, label: i.label ?? i.did, count: i.count }))} />
          </Card>
        </div>
      )}

      <Card title="Quản trị gốc"
        subtitle="Địa chỉ giữ quyền cao nhất — chỉ địa chỉ này cấp và thu hồi được quyền admin.">
        {root.data?.rootAdmin
          ? <Mono value={root.data.rootAdmin} truncate={false} />
          : <p className="text-sm text-ink-400">Không đọc được (chế độ không nối chuỗi)</p>}
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
            <Link className="btn-primary" to="/root">Mở màn hình quản trị gốc</Link>
          </div>
        )}
      </Card>

      <GasPanel />

      <Card title="Quản trị viên"
        subtitle="Cấp và thu hồi quyền admin là việc của root — xem màn hình quản trị gốc.">
        {admins.isLoading && <Spinner />}
        {!admins.isLoading && !admins.data?.length && <Empty title="Chưa có quản trị viên nào" />}
        {!!admins.data?.length && (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-xs uppercase tracking-wide text-ink-400">
                <tr><th className="py-2">Tên</th><th>DID</th><th>Ghi danh</th><th>Trên chuỗi</th></tr>
              </thead>
              <tbody className="divide-y divide-ink-100">
                {admins.data.map((r) => (
                  <tr key={r.address}>
                    <td className="py-2.5 font-medium text-ink-800">{r.label}</td>
                    <td><Mono value={r.did} /></td>
                    <td className="text-ink-600">
                      {new Date(r.createdAt).toLocaleDateString("vi-VN")}
                    </td>
                    <td>{r.activeOnChain
                      ? <Badge tone="ok">Đang hoạt động</Badge>
                      : <Badge tone="bad">Chưa/không còn quyền</Badge>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
