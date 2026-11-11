import { cfg } from "../config/index.js";

/** Địa chỉ package đã deploy. Cả 3 module nằm cùng một địa chỉ. */
export const PKG = cfg.CONTRACT_ADDRESS;

export const MODULE = {
  didRegistry: `${PKG}::did_registry`,
  authority: `${PKG}::authority`,
  vcRegistry: `${PKG}::vc_registry`,
} as const;

/**
 * Tên hàm entry — đối chiếu đúng với ABI đã deploy.
 * Gom về một chỗ vì đây chính là nơi đã sinh lỗi ở backend cũ:
 * gọi `vc_registry::issuer_vc` trong khi contract tên là `issue_vc`.
 */
export const ENTRY = {
  registerDid: `${MODULE.didRegistry}::register_did`,
  updateDidDocument: `${MODULE.didRegistry}::update_did_document`,
  /** Bí danh cũ của suspend_own_did — giữ để không vỡ ví đã phát hành. */
  deactivateDid: `${MODULE.didRegistry}::deactivate_did`,
  suspendOwnDid: `${MODULE.didRegistry}::suspend_own_did`,
  reactivateOwnDid: `${MODULE.didRegistry}::reactivate_own_did`,

  grantAdmin: `${MODULE.authority}::grant_admin`,
  revokeAdmin: `${MODULE.authority}::revoke_admin`,
  approveIssuer: `${MODULE.authority}::approve_issuer`,
  suspendIssuer: `${MODULE.authority}::suspend_issuer`,
  reactivateIssuer: `${MODULE.authority}::reactivate_issuer`,
  revokeIssuer: `${MODULE.authority}::revoke_issuer`,

  // Chuyển quyền root là HAI BƯỚC: root đề cử, người nhận tự ký chấp nhận.
  // Hàm `transfer_root` một bước đã bị bỏ — chuyển nhầm sang địa chỉ không ai
  // giữ khoá là khoá chết toàn bộ cây quyền lực (F-00).
  proposeRoot: `${MODULE.authority}::propose_root`,
  acceptRoot: `${MODULE.authority}::accept_root`,
  cancelRootTransfer: `${MODULE.authority}::cancel_root_transfer`,

  adminSuspendDid: `${MODULE.authority}::admin_suspend_did`,
  adminReactivateDid: `${MODULE.authority}::admin_reactivate_did`,
  adminRevokeDid: `${MODULE.authority}::admin_revoke_did`,

  issueVc: `${MODULE.vcRegistry}::issue_vc`,
  revokeVc: `${MODULE.vcRegistry}::revoke_vc`,
  suspendVc: `${MODULE.vcRegistry}::suspend_vc`,
  adminRevokeVc: `${MODULE.vcRegistry}::admin_revoke_vc`,
  adminReinstateVc: `${MODULE.vcRegistry}::admin_reinstate_vc`,
} as const;

export const VIEW = {
  resolveDid: `${MODULE.didRegistry}::resolve_did`,
  resolveDidByOwner: `${MODULE.didRegistry}::resolve_did_by_owner`,
  hasActiveDid: `${MODULE.didRegistry}::has_active_did`,
  totalDids: `${MODULE.didRegistry}::total_dids`,

  isActiveAdmin: `${MODULE.authority}::is_active_admin`,
  isActiveIssuer: `${MODULE.authority}::is_active_issuer`,
  canDelegate: `${MODULE.authority}::can_delegate`,
  getRootAdmin: `${MODULE.authority}::get_root_admin`,
  getPendingRoot: `${MODULE.authority}::get_pending_root`,
  getInfo: `${MODULE.authority}::get_info`,
  authorityStats: `${MODULE.authority}::stats`,
  getRolesPaginated: `${MODULE.authority}::get_roles_paginated`,

  getVcStatus: `${MODULE.vcRegistry}::get_vc_status`,
  getVcIdByHash: `${MODULE.vcRegistry}::get_vc_id_by_hash`,
  verifyIntegrity: `${MODULE.vcRegistry}::verify_integrity`,
  totalVcs: `${MODULE.vcRegistry}::total_vcs`,
  getLiveCounts: `${MODULE.vcRegistry}::get_live_counts`,
  getVcsPaginated: `${MODULE.vcRegistry}::get_vcs_paginated`,

  getDidsPaginated: `${MODULE.didRegistry}::get_dids_paginated`,
} as const;

/** Trạng thái vai trò on-chain — khớp authority.move. */
export const ROLE_STATUS: Record<number, string> = {
  1: "active",
  2: "revoked",
  3: "suspended",
};

/** Địa chỉ rỗng: không có ai đang chờ nhận quyền root. */
export const NO_PENDING_ROOT = "0x" + "0".repeat(64);

/** Bit vc_type — khớp sources/utils/constants.move */
export const VC_TYPE = {
  BACHELOR: 1,
  MASTER: 2,
  PHD: 4,
  TRANSCRIPT: 8,
  MICRO_CRED: 16,
  DELEGATION: 32,
} as const;

export const VC_TYPE_LABEL: Record<number, string> = {
  1: "Bằng cử nhân",
  2: "Bằng thạc sĩ",
  4: "Bằng tiến sĩ",
  8: "Bảng điểm",
  16: "Chứng chỉ ngắn hạn",
  32: "Chứng chỉ ủy quyền",
};

/** Trạng thái on-chain -> nhãn dùng chung với CSDL. */
export const DID_STATUS: Record<number, "active" | "suspended" | "revoked"> = {
  1: "active",
  2: "suspended",
  3: "revoked",
};

export const VC_STATUS: Record<number, "active" | "suspended" | "expired" | "revoked"> = {
  1: "active",
  2: "suspended",
  3: "expired",
  4: "revoked",
};
