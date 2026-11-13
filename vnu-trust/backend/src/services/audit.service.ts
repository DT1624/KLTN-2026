import { query } from "../db/pool.js";
import { logger } from "../utils/logger.js";

/**
 * Nhật ký kiểm toán cho các thao tác làm thay đổi trạng thái tin cậy.
 *
 * Bảng `audit_log` có sẵn trong lược đồ nhưng trước đây KHÔNG backend nào ghi
 * vào — tuyến `GET /admin/audit` luôn trả rỗng. Một hệ thống văn bằng mà không
 * ghi lại được "ai thu hồi cái gì, lúc nào" thì mất đúng thứ nó hứa hẹn.
 *
 * Tên hành động phải giống hệt ở backend Go (internal/services/audit.go),
 * nếu không lịch sử sẽ vỡ thành hai loại tuỳ theo backend nào xử lý yêu cầu.
 */
export type AuditAction =
  | "did.save"
  | "did.suspend"
  | "did.reactivate"
  | "did.revoke"
  | "vc.issue"
  | "vc.revoke"
  | "vc.suspend"
  | "vc.reinstate"
  // Nâng cấp 13/11: cấp lại (C3) và chuyển danh tính khi mất khoá (P4.2)
  | "vc.reissue"
  | "vc.link"
  | "did.migrate"
  | "share.create"
  | "share.revoke"
  // Quản trị quyền hạn trên chuỗi
  | "authority.grant_admin"
  | "authority.revoke_admin"
  | "authority.approve_issuer"
  | "authority.issuer_suspended"
  | "authority.issuer_active"
  | "authority.issuer_revoked"
  | "authority.propose_root"
  | "authority.accept_root"
  | "authority.cancel_root_transfer";

/**
 * Ghi nhật ký KHÔNG được làm hỏng thao tác chính: nếu ghi lỗi thì chỉ log lại,
 * không ném ra ngoài — người dùng đã thu hồi xong văn bằng rồi, không thể báo
 * họ là thất bại chỉ vì phần ghi chép phụ trợ gặp sự cố.
 */
export async function record(
  actor: string,
  action: AuditAction,
  target: string | null,
  detail: Record<string, unknown> = {},
): Promise<void> {
  try {
    await query(
      "INSERT INTO audit_log (actor, action, target, detail) VALUES ($1,$2,$3,$4)",
      [actor, action, target, JSON.stringify(detail)],
    );
  } catch (err) {
    logger.error({ err, actor, action, target }, "Không ghi được nhật ký kiểm toán");
  }
}
