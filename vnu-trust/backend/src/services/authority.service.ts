import { mapLimit } from "../utils/ttl-cache.js";
import { query, queryOne } from "../db/pool.js";
import { badRequest, conflict, forbidden } from "../utils/errors.js";
import { verifyTransaction, normalizeAddress, type ArgSpec } from "../chain/client.js";
import { utf8ToHex } from "../chain/registry.js";
import { ENTRY } from "../chain/abi.js";
import {
  getRootAdmin, getPendingRoot, getRoleInfo, isActiveAdmin, isActiveIssuer,
  canDelegate, liveCounts, getDelegator, resolveDidByOwner,
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

/**
 * Chống phát lại: sau khi giao dịch đã xác minh, trạng thái vai trò HIỆN TẠI trên
 * chuỗi phải đúng là trạng thái sắp ghi. Một giao dịch có thật nhưng cũ (vd.
 * revoke_issuer trước lần issuer được cấp lại) qua được mọi phép kiểm giao dịch,
 * và nếu không có bước này thì hạ được vai trò của người đang hoạt động trong chỉ mục.
 * Chế độ offline không có giao dịch nào để phát lại nên bỏ qua.
 */
function expectRoleStatus(target: string, status: "active" | "suspended" | "revoked", mask?: number) {
  return async (): Promise<void> => {
    if (OFFLINE) return;
    const info = await getRoleInfo(target);
    if (!info || info.status !== status || (mask !== undefined && info.vcTypeMask !== mask)) {
      throw conflict(
        `Trên chuỗi vai trò của địa chỉ này đang "${info?.status ?? "không có"}", không khớp thao tác — giao dịch đã cũ`,
      );
    }
  };
}

/**
 * Chế độ offline không có contract để chặn xung đột vai trò (M-04, R-05), nên
 * phải chặn ở đây: mỗi địa chỉ giữ tối đa MỘT vai trò. Khi nối chuỗi thì contract
 * đã chặn — giao dịch vi phạm không bao giờ thành công để mà có txHash.
 */
async function assertNoRoleConflictOffline(target: string, wanted: "admin" | "issuer"): Promise<void> {
  if (!OFFLINE) return;
  const role = (await getByAddress(normalizeAddress(target)))?.role;
  if (role === "root") throw conflict("Root không được giữ thêm vai trò admin hay issuer");
  if (wanted === "admin" && role === "issuer") throw conflict("Địa chỉ đang là issuer — thu hồi quyền issuer trước");
  if (wanted === "issuer" && role === "admin") throw conflict("Địa chỉ đang là admin — thu hồi quyền admin trước");
  if (role === wanted) throw conflict(`Địa chỉ đã là ${wanted}`);
}

async function applyAuthorityTx(opts: {
  actor: EntityRow;
  target: string;
  txHash: string;
  expectedFunction: string;
  newRole: Role | null;
  auditAction: AuditAction;
  detail: Record<string, unknown>;
  /**
   * Tham số giao dịch phải khớp (S-02). Mặc định: tham số đầu là địa chỉ đích.
   * Thiếu bước này thì một giao dịch approve_issuer thật phong được issuer cho
   * địa chỉ BẤT KỲ, và dùng lại được bao nhiêu lần cũng được.
   */
  args?: ArgSpec[];
  /** Kiểm thêm sau khi giao dịch đã xác minh, trước khi đổi chỉ mục. */
  beforeSync?: () => Promise<void>;
}): Promise<AuthorityActionResult> {
  const target = normalizeAddress(opts.target);

  await verifyTransaction(opts.txHash, {
    expectedFunction: opts.expectedFunction,
    expectedSender: opts.actor.address,
    args: opts.args ?? [{ address: target }],
  });

  if (opts.beforeSync) await opts.beforeSync();

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
  await assertNoRoleConflictOffline(target, "admin");
  return applyAuthorityTx({
    actor,
    target,
    txHash,
    expectedFunction: ENTRY.grantAdmin,
    newRole: "admin",
    auditAction: "authority.grant_admin",
    detail: {},
    beforeSync: expectRoleStatus(target, "active"),
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
    beforeSync: expectRoleStatus(target, "revoked"),
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
  await assertNoRoleConflictOffline(target, "issuer");
  return applyAuthorityTx({
    actor,
    target,
    txHash,
    expectedFunction: ENTRY.approveIssuer,
    newRole: "issuer",
    auditAction: "authority.approve_issuer",
    detail: { vcTypeMask, expiresAt },
    args: [{ address: target }, { u64: vcTypeMask }, null, null, { u64: expiresAt }],
    beforeSync: expectRoleStatus(target, "active", vcTypeMask),
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
    beforeSync: expectRoleStatus(target, next),
  });
}

// ---------------------------------------------------------------------------
// Uỷ quyền: issuer có bit VC_DELEGATION cấp và quản lý sub-issuer (M-02, R-04)
// ---------------------------------------------------------------------------

/** Mask nằm trọn trong 6 bit đã định nghĩa; bit 32 = uỷ quyền, chỉ root cấp. */
const DELEGATION_BIT = 32;

/**
 * Issuer uỷ quyền cấp sub-issuer. Contract quyết định toàn bộ luật (mask con ⊆
 * mask cha, không có bit uỷ quyền, hạn không vượt hạn cha, địa chỉ chưa từng là
 * issuer); backend chỉ chặn sớm những gì rẻ và xác minh giao dịch.
 * Chế độ offline không biết bit uỷ quyền (chỉ có trên chuỗi) nên từ chối thẳng.
 */
export async function approveSubIssuer(
  actor: EntityRow,
  target: string,
  vcTypeMask: number,
  expiresAt: number,
  txHash: string,
): Promise<AuthorityActionResult> {
  if (OFFLINE) throw forbidden("Chế độ không nối chuỗi không xác định được quyền uỷ quyền");
  if ((vcTypeMask & DELEGATION_BIT) !== 0) throw badRequest("Sub-issuer không được nhận bit uỷ quyền");
  if (!(await canDelegate(actor.address))) {
    throw forbidden("Quyền issuer của bạn không có bit uỷ quyền, hoặc đã hết hiệu lực");
  }
  return approveIssuer(actor, target, vcTypeMask, expiresAt, txHash);
}

/**
 * Issuer cha tạm ngưng / thu hồi sub-issuer do CHÍNH MÌNH cấp. Không kích hoạt
 * lại được — tự ngưng rồi tự bật là né kiểm soát; việc đó để admin.
 */
export async function setSubIssuerStatus(
  actor: EntityRow,
  target: string,
  next: "suspended" | "revoked",
  reason: string,
  txHash: string,
): Promise<AuthorityActionResult> {
  if (OFFLINE) throw forbidden("Chế độ không nối chuỗi không xác định được quan hệ uỷ quyền");
  const parent = await getDelegator(target);
  if (parent !== normalizeAddress(actor.address)) {
    throw forbidden("Địa chỉ này không phải sub-issuer do bạn cấp");
  }
  return setIssuerStatus(actor, target, next, reason, txHash);
}

/**
 * Sub-issuer do issuer này đã cấp, đọc từ nhật ký kiểm toán (chuỗi không có view
 * liệt kê theo cha). Trạng thái hiện hành đọc lại từ chuỗi cho từng địa chỉ.
 */
export async function delegationSnapshot(actor: EntityRow) {
  const me = normalizeAddress(actor.address);
  const [allowed, info] = await Promise.all([canDelegate(me), getRoleInfo(me)]);
  const rows = await query<{ target: string }>(
    `SELECT DISTINCT target FROM audit_log
      WHERE actor = $1 AND action = 'authority.approve_issuer' AND target IS NOT NULL`,
    [me],
  );
  // P5: trước đây hỏi chuỗi TUẦN TỰ 2 lần mỗi sub-issuer; nay song song (trần 8),
  // hai câu hỏi của cùng một địa chỉ chạy cùng lúc, thứ tự kết quả giữ nguyên.
  const found = await mapLimit(rows, 8, async ({ target }) => {
    const [parent, role, entity] = await Promise.all([getDelegator(target), getRoleInfo(target), getByAddress(target)]);
    if (parent !== me) return null; // đã được root/admin cấp lại
    return {
      address: target,
      label: entity?.label ?? null,
      vcTypeMask: role?.vcTypeMask ?? 0,
      expiresAt: role?.expiresAt ?? 0,
      status: role?.status ?? "unknown",
    };
  });
  const subIssuers = found.filter((x): x is NonNullable<typeof x> => x !== null);
  return {
    canDelegate: allowed,
    /** Bit loại văn bằng được phép giao cho sub-issuer (mask của mình, bỏ bit uỷ quyền). */
    delegableMask: (info?.vcTypeMask ?? 0) & ~DELEGATION_BIT,
    /** Hạn của mình; sub-issuer không được sống lâu hơn (0 = vĩnh viễn). */
    expiresAt: info?.expiresAt ?? 0,
    subIssuers,
    source: OFFLINE ? "db-index" : "chain",
  };
}

// ---------------------------------------------------------------------------
// Admin kiểm duyệt DID (M-01, M-08)
// ---------------------------------------------------------------------------

const DID_MODERATION = {
  suspended: { fn: ENTRY.adminSuspendDid, action: "did.suspend" },
  active: { fn: ENTRY.adminReactivateDid, action: "did.reactivate" },
  revoked: { fn: ENTRY.adminRevokeDid, action: "did.revoke" },
} as const;

/**
 * Admin khoá / mở / thu hồi DID của một địa chỉ. Thu hồi DID trên chuỗi thu hồi
 * luôn vai trò admin/issuer của địa chỉ đó (M-01), nên chỉ mục hạ vai trò về
 * holder cho khớp. Admin thường không được đụng DID của root hay admin khác.
 */
export async function moderateDid(
  actor: EntityRow,
  target: string,
  next: "suspended" | "active" | "revoked",
  reason: string,
  txHash: string,
) {
  const addr = normalizeAddress(target);
  const entity = await getByAddress(addr);
  if (OFFLINE) {
    if (entity?.role === "root") throw forbidden("Không được tác động lên DID của root");
    if (actor.role !== "root" && entity?.role === "admin") {
      throw forbidden("Chỉ root mới tác động được lên DID của admin khác");
    }
  }
  const { fn, action } = DID_MODERATION[next];
  await verifyTransaction(txHash, {
    expectedFunction: fn,
    expectedSender: actor.address,
    args: [{ address: addr }, { bytes: utf8ToHex(reason) }],
  });
  // Chống phát lại: DID trên chuỗi hiện tại phải đúng trạng thái sắp ghi.
  if (!OFFLINE) {
    const onChain = await resolveDidByOwner(addr);
    if (!onChain || onChain.status !== next) {
      throw conflict(`Trên chuỗi DID đang "${onChain?.status ?? "không có"}", không khớp thao tác — giao dịch đã cũ`);
    }
  }
  await query(
    `UPDATE did_documents d SET status = $2, updated_at = now()
       FROM entities e WHERE e.id = d.entity_id AND e.address = $1 AND d.status <> 'revoked'`,
    [addr, next],
  );
  let appRole = entity?.role ?? null;
  if (next === "revoked" && (appRole === "admin" || appRole === "issuer")) {
    appRole = await syncAppRole(addr, "holder");
  }
  await record(actor.address, action, addr, { reason, txHash });
  return { address: addr, txHash, status: next, appRole, notRegisteredInApp: entity === null };
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
    args: [],
    // accept_root không có tham số nên giao dịch CŨ cũng hợp lệ: root trước đây
    // đem hash accept_root của mình gửi lại là giành lại "root" trong chỉ mục
    // và hạ root thật xuống admin. Phải hỏi chuỗi: root HIỆN TẠI là ai.
    beforeSync: async () => {
      if (OFFLINE) return;
      const root = await getRootAdmin();
      if (!root || normalizeAddress(root) !== normalizeAddress(actor.address)) {
        throw forbidden("Trên chuỗi, tài khoản này hiện không phải root_admin — giao dịch accept_root đã cũ");
      }
    },
  });

  // Chỉ có MỘT root. Chuỗi chỉ giữ đúng một `root_admin`, nên để hai hàng
  // role='root' trong chỉ mục là nói dối về chính thứ vừa thay đổi. Root cũ về
  // holder: trên chuỗi họ KHÔNG có bản ghi admin nào (chuyển root không cấp quyền
  // admin cho root cũ). Trước đây chỉ mục ghi "admin" — ở chế độ offline điều đó
  // còn để root cũ giữ nguyên quyền quản trị.
  await query(
    "UPDATE entities SET role = 'holder', updated_at = now() WHERE role = 'root' AND address <> $1",
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
    args: [],
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
