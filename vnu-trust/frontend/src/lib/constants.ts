/**
 * Hằng số dùng chung của giao diện, khớp với `contracts/sources/utils/constants.move`.
 * Gom về một chỗ vì trước đây bảng loại văn bằng bị chép ở cả Admin lẫn Issuer
 * và đã lệch nhau: một bên thiếu bit uỷ quyền.
 */

export interface VcTypeDef {
  bit: number;
  label: string;
  /** Bit uỷ quyền: chỉ root mới cấp được (xem approve_issuer trong authority.move). */
  rootOnly?: boolean;
}

export const VC_TYPES: VcTypeDef[] = [
  { bit: 1, label: "Bằng cử nhân" },
  { bit: 2, label: "Bằng thạc sĩ" },
  { bit: 4, label: "Bằng tiến sĩ" },
  { bit: 8, label: "Bảng điểm" },
  { bit: 16, label: "Chứng chỉ ngắn hạn" },
  { bit: 32, label: "Chứng chỉ uỷ quyền", rootOnly: true },
];

/** Các loại văn bằng thật sự cấp cho người học (không tính chứng chỉ uỷ quyền). */
export const ISSUABLE_VC_TYPES = VC_TYPES.filter((t) => !t.rootOnly);

export const VC_TYPE_DELEGATION = 32;

/** Gộp các bit thành nhãn đọc được. */
export function maskLabel(mask: number): string {
  const parts = VC_TYPES.filter((t) => (mask & t.bit) !== 0).map((t) => t.label);
  return parts.length ? parts.join(", ") : `Không có quyền nào (mask ${mask})`;
}

export type Tone = "ok" | "warn" | "bad" | "info" | "muted";

/**
 * Nhãn tiếng Việt cho tên hành động trong nhật ký kiểm toán. Tên hành động do
 * backend quyết định và phải giống hệt nhau ở cả bản TS lẫn bản Go.
 */
export const AUDIT_ACTION: Record<string, { label: string; tone: Tone; group: AuditGroup }> = {
  "did.save": { label: "Ghi nhận DID", tone: "info", group: "did" },
  "vc.issue": { label: "Cấp văn bằng", tone: "ok", group: "vc" },
  "vc.revoke": { label: "Thu hồi văn bằng", tone: "bad", group: "vc" },
  "vc.suspend": { label: "Tạm ngưng văn bằng", tone: "warn", group: "vc" },
  "vc.reinstate": { label: "Kích hoạt lại văn bằng", tone: "ok", group: "vc" },
  "share.create": { label: "Tạo liên kết chia sẻ", tone: "info", group: "share" },
  "share.revoke": { label: "Thu hồi liên kết chia sẻ", tone: "warn", group: "share" },
  "authority.grant_admin": { label: "Cấp quyền quản trị viên", tone: "ok", group: "authority" },
  "authority.revoke_admin": { label: "Thu hồi quyền quản trị viên", tone: "bad", group: "authority" },
  "authority.approve_issuer": { label: "Phê duyệt đơn vị cấp bằng", tone: "ok", group: "authority" },
  "authority.issuer_suspended": { label: "Tạm ngưng đơn vị cấp bằng", tone: "warn", group: "authority" },
  "authority.issuer_active": { label: "Kích hoạt lại đơn vị cấp bằng", tone: "ok", group: "authority" },
  "authority.issuer_revoked": { label: "Thu hồi quyền đơn vị cấp bằng", tone: "bad", group: "authority" },
  "authority.propose_root": { label: "Đề cử quản trị gốc", tone: "warn", group: "authority" },
  "authority.accept_root": { label: "Nhận quyền quản trị gốc", tone: "bad", group: "authority" },
  "authority.cancel_root_transfer": { label: "Huỷ đề cử quản trị gốc", tone: "muted", group: "authority" },
};

export type AuditGroup = "did" | "vc" | "share" | "authority";

export const AUDIT_GROUPS: { id: AuditGroup | "all"; label: string }[] = [
  { id: "all", label: "Tất cả" },
  { id: "authority", label: "Cấp quyền" },
  { id: "vc", label: "Văn bằng" },
  { id: "did", label: "Danh tính" },
  { id: "share", label: "Chia sẻ" },
];

export const auditMeta = (action: string) =>
  AUDIT_ACTION[action] ?? { label: action, tone: "muted" as Tone, group: "did" as AuditGroup };
