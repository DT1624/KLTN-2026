import { Link, Navigate, useLocation } from "react-router-dom";
import type { ReactNode } from "react";
import { useWallet } from "../hooks/useWallet";
import { Spinner, Alert, roleLabel } from "./ui";
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
      <Alert tone="bad" title="Trang này không dành cho vai trò của bạn">
        <p>
          Trang này dành cho: {roles.map((r) => roleLabel(r)).join(", ")}. Ví hiện tại có vai trò{" "}
          <strong>{roleLabel(wallet.role)}</strong>.
        </p>
        <p className="mt-2"><Link className="link" to="/account">Về trang Tài khoản</Link></p>
      </Alert>
    );
  }
  return <>{children}</>;
}
