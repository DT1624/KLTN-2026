import { query, queryOne } from "../db/pool.js";
import { badRequest, forbidden } from "../utils/errors.js";
import { verifyTransaction, normalizeAddress } from "../chain/client.js";
import { ENTRY } from "../chain/abi.js";
import {
  getRootAdmin, getPendingRoot, getRoleInfo, isActiveAdmin, isActiveIssuer,
  canDelegate, liveCounts,
} from "../chain/registry.js";
import { OFFLINE } from "../chain/offline.js";
import { getByAddress } from "./entity.service.js";
import { record, type AuditAction } from "./audit.service.js";
import type { EntityRow, Role } from "../types/index.js";

/**
 * Quản trị vai trò TRÊN CHUỖI.
 *
 * Mô hình giống hệt phần còn lại của hệ thống: ví phi lưu ký nên chính người
 * dùng ký và gửi giao dịch, backend chỉ **xác minh giao dịch đó có thật** rồi
 * cập nhật chỉ mục trong CSDL. Nói cách khác, quyền hạn do contract quyết
 * định — backend không tự ý phong ai làm gì.
 *
 * Màn hình này từng bị hoãn vì contract dính F-00 (root đóng băng ở địa chỉ
 * không ai giữ khoá) và F-01 (approve_issuer luôn đòi hash 32 byte). Cả hai
 * đã sửa nên tuyến này mới có ý nghĩa.
 */

export interface AuthorityActionResult {
  address: string;
  txHash: string;
  /** Vai trò trong CSDL sau khi cập nhật, hoặc null nếu địa chỉ chưa ghi danh. */
  appRole: Role | null;
  /** Địa chỉ có quyền trên chuỗi nhưng chưa đăng ký trong ứng dụng. */
  notRegisteredInApp: boolean;
}

/**
 * Thao tác chỉ root mới được làm.
 *
 * Khi còn nối chuỗi thì `verifyTransaction` đã là bằng chứng mạnh nhất: giao
 * dịch thành công nghĩa là chính contract đã chấp nhận người gửi là root. Rào
 * này chủ yếu để chế độ VERIFY_ONCHAIN=false không trở thành cửa sau — lúc đó
 * không có giao dịch nào để xác minh cả.
 */
async function assertRootAuthority(actor: EntityRow): Promise<void> {
  if (OFFLINE) {
    if (actor.role !== "root") {
      throw forbidden("Chỉ tài khoản root mới thực hiện được thao tác này");
    }
    return;
  }
  const root = await getRootAdmin();
  if (!root || normalizeAddress(root) !== normalizeAddress(actor.address)) {
    throw forbidden("Chỉ root_admin trên chuỗi mới thực hiện được thao tác này");
  }
}

/** Đổi vai trò trong chỉ mục CSDL. Địa chỉ chưa ghi danh thì bỏ qua, không lỗi. */
async function syncAppRole(address: string, role: Role): Promise<Role | null> {
  const entity = await getByAddress(address);
  if (!entity) return null;
  // Root trong CSDL không bị hạ xuống bởi thao tác thường — chỉ accept_root đổi.
  const row = await queryOne<EntityRow>(
    "UPDATE entities SET role = $2, updated_at = now() WHERE address = $1 RETURNING *",
    [address, role],
  );
  return row?.role ?? null;
}

async function applyAuthorityTx(opts: {
  actor: EntityRow;
  target: string;
  txHash: string;
  expectedFunction: string;
  newRole: Role | null;
  auditAction: AuditAction;
  detail: Record<string, unknown>;
}): Promise<AuthorityActionResult> {
  const target = normalizeAddress(opts.target);

  await verifyTransaction(opts.txHash, {
    expectedFunction: opts.expectedFunction,
    expectedSender: opts.actor.address,
  });

  const entity = await getByAddress(target);
  const appRole = opts.newRole ? await syncAppRole(target, opts.newRole) : (entity?.role ?? null);

  await record(opts.actor.address, opts.auditAction, target, {
    ...opts.detail,
    txHash: opts.txHash,
  });

  return {
    address: target,
    txHash: opts.txHash,
    appRole,
    notRegisteredInApp: entity === null,
  };
}

export async function grantAdmin(
  actor: EntityRow,
  target: string,
  txHash: string,
): Promise<AuthorityActionResult> {
  await assertRootAuthority(actor);
  return applyAuthorityTx({
    actor,
    target,
    txHash,
    expectedFunction: ENTRY.grantAdmin,
    newRole: "admin",
    auditAction: "authority.grant_admin",
    detail: {},
  });
}

export async function revokeAdmin(
  actor: EntityRow,
  target: string,
  reason: string,
  txHash: string,
): Promise<AuthorityActionResult> {
  await assertRootAuthority(actor);
  if (normalizeAddress(target) === normalizeAddress(actor.address)) {
    throw badRequest("Root không thể tự thu hồi quyền admin của chính mình");
  }
  return applyAuthorityTx({
    actor,
    target,
    txHash,
    expectedFunction: ENTRY.revokeAdmin,
    // Mất quyền admin thì quay về holder — vẫn giữ DID và văn bằng của mình.
    newRole: "holder",
    auditAction: "authority.revoke_admin",
    detail: { reason },
  });
}

export async function approveIssuer(
  actor: EntityRow,
  target: string,
  vcTypeMask: number,
  expiresAt: number,
  txHash: string,
): Promise<AuthorityActionResult> {
  if (vcTypeMask <= 0) throw badRequest("vcTypeMask phải là số dương");
  if (expiresAt !== 0 && expiresAt * 1000 <= Date.now()) {
    throw badRequest("Thời điểm hết hạn phải ở tương lai (0 = vĩnh viễn)");
  }
  return applyAuthorityTx({
    actor,
    target,
    txHash,
    expectedFunction: ENTRY.approveIssuer,
    newRole: "issuer",
    auditAction: "authority.approve_issuer",
    detail: { vcTypeMask, expiresAt },
  });
}

const ISSUER_STATUS_FN: Record<string, string> = {
  suspended: ENTRY.suspendIssuer,
  active: ENTRY.reactivateIssuer,
  revoked: ENTRY.revokeIssuer,
};

export async function setIssuerStatus(
  actor: EntityRow,
  target: string,
  next: "suspended" | "active" | "revoked",
  reason: string,
  txHash: string,
): Promise<AuthorityActionResult> {
  const fn = ISSUER_STATUS_FN[next];
  if (!fn) throw badRequest("Trạng thái issuer không hợp lệ");
  return applyAuthorityTx({
    actor,
    target,
    txHash,
    expectedFunction: fn,
    // Tạm ngưng thì vẫn là issuer (quyền còn đó, chỉ bị khoá); thu hồi thì không.
    newRole: next === "revoked" ? "holder" : null,
    auditAction: `authority.issuer_${next}` as AuditAction,
    detail: { reason },
  });
}

export async function proposeRoot(
  actor: EntityRow,
  target: string,
  txHash: string,
): Promise<AuthorityActionResult> {
  await assertRootAuthority(actor);
  if (normalizeAddress(target) === normalizeAddress(actor.address)) {
    throw badRequest("Đề cử chính mình làm root là thao tác vô nghĩa");
  }
  // Đề cử một địa chỉ chưa ghi danh là cách nhanh nhất để mất quyền root:
  // không ai chứng minh được có người giữ khoá của địa chỉ đó.
  const entity = await getByAddress(normalizeAddress(target));
  if (!entity) {
    throw badRequest(
      "Địa chỉ được đề cử chưa đăng ký trong hệ thống — hãy để họ đăng ký DID trước khi đề cử",
    );
  }
  return applyAuthorityTx({
    actor,
    target,
    txHash,
    expectedFunction: ENTRY.proposeRoot,
    newRole: null,
    auditAction: "authority.propose_root",
    detail: {},
  });
}

/**
 * Người được đề cử tự ký nhận quyền root. Chính chữ ký này là bằng chứng họ
 * giữ khoá riêng — đó là điều mà chuyển root một bước không chứng minh được.
 */
export async function acceptRoot(actor: EntityRow, txHash: string): Promise<AuthorityActionResult> {
  const result = await applyAuthorityTx({
    actor,
    target: actor.address,
    txHash,
    expectedFunction: ENTRY.acceptRoot,
    newRole: "root",
    auditAction: "authority.accept_root",
    detail: {},
  });

  // Chỉ có MỘT root. Chuỗi chỉ giữ đúng một `root_admin`, nên để hai hàng
  // role='root' trong chỉ mục là nói dối về chính thứ vừa thay đổi. Root cũ
  // xuống admin — họ vẫn là người có thẩm quyền, chỉ không còn là gốc.
  await query(
    "UPDATE entities SET role = 'admin', updated_at = now() WHERE role = 'root' AND address <> $1",
    [normalizeAddress(actor.address)],
  );

  return result;
}

export async function cancelRootTransfer(
  actor: EntityRow,
  txHash: string,
): Promise<AuthorityActionResult> {
  await assertRootAuthority(actor);
  return applyAuthorityTx({
    actor,
    target: actor.address,
    txHash,
    expectedFunction: ENTRY.cancelRootTransfer,
    newRole: null,
    auditAction: "authority.cancel_root_transfer",
    detail: {},
  });
}

/** Ảnh chụp quyền root hiện tại, kèm đề cử đang chờ (nếu có). */
export async function rootSnapshot(callerAddress: string) {
  const [root, pending] = await Promise.all([getRootAdmin(), getPendingRoot()]);
  const caller = normalizeAddress(callerAddress);
  return {
    rootAdmin: root,
    pendingRoot: pending,
    callerIsRoot: root !== null && normalizeAddress(root) === caller,
    callerIsPendingRoot: pending !== null && normalizeAddress(pending) === caller,
    /** Chế độ không nối chuỗi không đọc được root — nói thẳng thay vì đoán. */
    source: OFFLINE ? "db-index" : "chain",
  };
}

/** Toàn bộ những gì chuỗi biết về quyền hạn của một địa chỉ. */
export async function roleSnapshot(address: string) {
  const addr = normalizeAddress(address);
  const [admin, issuer, delegate, info, counts] = await Promise.all([
    isActiveAdmin(addr),
    isActiveIssuer(addr),
    canDelegate(addr),
    getRoleInfo(addr),
    // Cùng một địa chỉ ở cả hai vế: trả về "đã cấp bao nhiêu" và "đang giữ
    // bao nhiêu" trong một lượt gọi.
    liveCounts(addr, addr),
  ]);
  const entity = await getByAddress(addr);
  return {
    address: addr,
    isActiveAdmin: admin,
    isActiveIssuer: issuer,
    canDelegate: delegate,
    role: info,
    appRole: entity?.role ?? null,
    appLabel: entity?.label ?? null,
    /** Số văn bằng còn hiệu lực — cận trên, vì bộ đếm on-chain không trừ VC hết hạn. */
    liveCredentials: counts,
    source: OFFLINE ? "db-index" : "chain",
  };
}
