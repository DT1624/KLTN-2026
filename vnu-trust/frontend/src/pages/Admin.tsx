import { Link } from "react-router-dom";
import { useAuthorityRoot, useMe } from "../hooks/useChain";
import { TabBar, useTabs, type TabDef } from "../components/Tabs";
import OverviewTab from "./admin/OverviewTab";
import IssuersTab from "./admin/IssuersTab";
import IdentitiesTab from "./admin/IdentitiesTab";
import CredentialsTab from "./admin/CredentialsTab";
import AuditTab from "./admin/AuditTab";

/**
 * Màn hình quản trị, chia theo việc.
 *
 * Trước đây đây là một trang dài dằng dặc: số liệu, tra cứu, cấp quyền, cưỡng
 * chế văn bằng, chuyển quyền gốc và nhật ký nối đuôi nhau trong cùng một cột.
 * Muốn xem nhật ký phải cuộn qua toàn bộ phần cấp quyền — và tệ hơn, các nút
 * nguy hiểm nằm ngay cạnh nhau.
 *
 * Nay mỗi việc một tab, tab ghi vào URL (`?tab=…`) để gửi được đường dẫn thẳng
 * tới đúng mục. Thao tác chỉ-root nằm ở màn hình riêng `/root`.
 */
export default function Admin() {
  const me = useMe();
  const root = useAuthorityRoot();

  const tabs: TabDef[] = [
    { id: "tong-quan", label: "Tổng quan" },
    { id: "cap-bang", label: "Đơn vị cấp bằng" },
    { id: "danh-tinh", label: "Danh tính" },
    { id: "van-bang", label: "Văn bằng" },
    { id: "nhat-ky", label: "Nhật ký & truy vết" },
  ];
  const { active, select, visible } = useTabs(tabs);

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-ink-900">Quản trị hệ thống</h1>
          <p className="text-sm text-ink-600 mt-1">
            {me.data?.onChain.isActiveAdmin
              ? "Ví của bạn ký mọi thao tác — không cần dán mã giao dịch."
              : "Đối chiếu dữ liệu ứng dụng với quyền thật trên chuỗi."}
          </p>
        </div>
        {root.data?.callerIsRoot && (
          <Link className="btn-ghost" to="/root">Quản trị gốc →</Link>
        )}
      </header>

      <TabBar tabs={visible} active={active} onSelect={select} />

      {active === "tong-quan" && <OverviewTab />}
      {active === "cap-bang" && <IssuersTab />}
      {active === "danh-tinh" && <IdentitiesTab />}
      {active === "van-bang" && <CredentialsTab />}
      {active === "nhat-ky" && <AuditTab />}
    </div>
  );
}
