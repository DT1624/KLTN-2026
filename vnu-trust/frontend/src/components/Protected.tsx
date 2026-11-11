import { Navigate, useLocation } from "react-router-dom";
import type { ReactNode } from "react";
import { useWallet } from "../hooks/useWallet";
import { Spinner, Alert } from "./ui";
import type { Role } from "../lib/api";

/**
 * Chặn truy cập ở phía giao diện. Quyền thật vẫn do máy chủ và hợp đồng quyết định.
 * Bỏ trống `roles` nghĩa là chỉ cần mở ví — dùng cho những trang tự kiểm quyền
 * bằng dữ liệu on-chain (ví dụ màn hình quản trị gốc).
 */
export default function Protected({ roles, children }: { roles?: Role[]; children: ReactNode }) {
  const { wallet, loading } = useWallet();
  const loc = useLocation();

  if (loading) return <Spinner label="Đang kiểm tra ví…" />;
  if (!wallet) return <Navigate to="/wallet" state={{ from: loc.pathname }} replace />;

  if (roles && !roles.includes(wallet.role)) {
    return (
      <Alert tone="bad" title="Không đủ quyền truy cập">
        Trang này dành cho: {roles?.join(", ")}. Ví hiện tại có vai trò <strong>{wallet.role}</strong>.
      </Alert>
    );
  }
  return <>{children}</>;
}
