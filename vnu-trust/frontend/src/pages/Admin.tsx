import { Link } from "react-router-dom";
import { useAuthorityRoot, useMe } from "../hooks/useChain";
import { TabBar, TabPanel, useTabs, type TabDef } from "../components/Tabs";
import { useTitle } from "../hooks/useTitle";
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
  useTitle("Quản trị");
  const me = useMe();
  const root = useAuthorityRoot();

  const tabs: TabDef[] = [
    { id: "tong-quan", label: "Tổng quan" },
    { id: "cap-bang", label: "Đơn vị cấp bằng" },
    { id: "danh-tinh", label: "Danh tính" },
    { id: "van-bang", label: "Văn bằng" },
    { id: "nhat-ky", label: "Nhật ký và truy vết" },
  ];
  const { active, select, visible } = useTabs(tabs);

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl sm:text-3xl font-bold tracking-tight">Quản trị</h1>
          <p className="text-muted mt-2 max-w-prose">
            {me.data?.onChain.isActiveAdmin
              ? "Ví của bạn ký mọi thao tác quản trị."
              : "Đối chiếu dữ liệu ứng dụng với quyền thật trên chuỗi."}
          </p>
        </div>
        {root.data?.callerIsRoot && (
          <Link className="btn-secondary" to="/root">Quản trị gốc</Link>
        )}
      </header>

      <div className="space-y-6">
        <TabBar tabs={visible} active={active} onSelect={select} />

        {active === "tong-quan" && <TabPanel id="tong-quan"><OverviewTab /></TabPanel>}
        {active === "cap-bang" && <TabPanel id="cap-bang"><IssuersTab /></TabPanel>}
        {active === "danh-tinh" && <TabPanel id="danh-tinh"><IdentitiesTab /></TabPanel>}
        {active === "van-bang" && <TabPanel id="van-bang"><CredentialsTab /></TabPanel>}
        {active === "nhat-ky" && <TabPanel id="nhat-ky"><AuditTab /></TabPanel>}
      </div>
    </div>
  );
}
