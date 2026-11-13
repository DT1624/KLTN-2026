import { Router } from "express";
import { z } from "zod";
import { requireAuth, requireRole, requireOnChainRole } from "../middleware/auth.js";
import { listByRole } from "../services/entity.service.js";
import { requireByVcId, changeStatus, systemAnalytics } from "../services/vc.service.js";
import { requireByAddress } from "../services/entity.service.js";
import { sendOk, param } from "../utils/http.js";
import { query } from "../db/pool.js";
import { authorityStats, getRootAdmin, isActiveAdmin, isActiveIssuer } from "../chain/registry.js";
import * as authority from "../services/authority.service.js";
import * as review from "../services/review.service.js";
import { zBatchBody } from "./issuer.routes.js";
import { zAddress, zTxHash, zPagination } from "../utils/validate.js";

/** Thân yêu cầu chung của mọi thao tác quản trị quyền: lý do + mã giao dịch. */
const zReasonTx = z.object({
  reason: z.string().trim().min(2).max(500),
  txHash: zTxHash,
});

const router = Router();
// V1 (13/11/2026): MỌI tuyến admin đối chiếu quyền trên chuỗi, không riêng tuyến
// ghi. Trước đây tuyến đọc (nhật ký, toàn văn văn bằng, số liệu) chỉ xem vai trò
// trong CSDL — admin bị thu hồi NGOÀI ứng dụng (CLI, client khác) vẫn đọc được dữ
// liệu riêng tư của mọi người cho tới khi chỉ mục được sửa tay. Offline thì
// isActiveAdmin đọc CSDL nên hành vi không đổi.
router.use(requireAuth, requireRole("admin", "root"), requireOnChainRole("admin"));

/** Bảng điều khiển quản trị: đối chiếu số liệu ứng dụng với số liệu trên chuỗi. */
router.get("/overview", async (_req, res, next) => {
  try {
    const [chain, root, appCounts] = await Promise.all([
      authorityStats(),
      getRootAdmin(),
      query<{ role: string; count: string }>(
        "SELECT role::text AS role, count(*)::text AS count FROM entities GROUP BY role",
      ),
    ]);
    const app: Record<string, number> = {};
    for (const r of appCounts) app[r.role] = Number(r.count);

    sendOk(res, {
      onChain: { admins: chain.admins, issuers: chain.issuers, rootAdmin: root },
      inApp: app,
      /** Lệch giữa số issuer trên chuỗi và số đã ghi danh trong ứng dụng. */
      issuerDrift: chain.issuers - (app.issuer ?? 0),
    });
  } catch (e) {
    next(e);
  }
});

/** Số liệu cho biểu đồ của màn hình quản trị. */
router.get("/analytics", async (_req, res, next) => {
  try {
    sendOk(res, await systemAnalytics());
  } catch (e) {
    next(e);
  }
});

/** Danh sách issuer kèm trạng thái thật trên chuỗi. */
router.get("/issuers", async (req, res, next) => {
  try {
    const { limit, offset } = zPagination.parse(req.query);
    const rows = await listByRole("issuer", limit, offset);
    const enriched = await Promise.all(
      rows.map(async (e) => ({
        address: e.address,
        did: e.did,
        label: e.label,
        createdAt: e.created_at,
        activeOnChain: await isActiveIssuer(e.address),
      })),
    );
    sendOk(res, enriched);
  } catch (e) {
    next(e);
  }
});

router.get("/admins", async (req, res, next) => {
  try {
    const { limit, offset } = zPagination.parse(req.query);
    const rows = await listByRole("admin", limit, offset);
    const enriched = await Promise.all(
      rows.map(async (e) => ({
        address: e.address,
        did: e.did,
        label: e.label,
        createdAt: e.created_at,
        activeOnChain: await isActiveAdmin(e.address),
      })),
    );
    sendOk(res, enriched);
  } catch (e) {
    next(e);
  }
});

/** Kiểm tra một địa chỉ bất kỳ có quyền gì trên chuỗi. */
router.get("/check/:address", async (req, res, next) => {
  try {
    const address = zAddress.parse(param(req.params, "address"));
    const [admin, issuer] = await Promise.all([isActiveAdmin(address), isActiveIssuer(address)]);
    sendOk(res, { address, isActiveAdmin: admin, isActiveIssuer: issuer });
  } catch (e) {
    next(e);
  }
});

/**
 * Một văn bằng theo mã, cho màn hình quản trị.
 *
 * Admin cần **số hiệu on-chain** (`on_chain_vc_id`) để ký được
 * `admin_revoke_vc` / `admin_reinstate_vc` — hàm trên chuỗi nhận u64 chứ không
 * nhận chuỗi `urn:uuid:…`. Trước đây giao diện bắt gõ tay con số đó; gõ nhầm
 * một chữ số là thu hồi nhầm bằng của người khác.
 */
router.get("/credentials/:vcId", async (req, res, next) => {
  try {
    sendOk(res, await requireByVcId(param(req.params, "vcId")));
  } catch (e) {
    next(e);
  }
});

/** Admin cưỡng chế thu hồi một VC (gian lận, quyết định hành chính). */
router.post("/credentials/:vcId/revoke", async (req, res, next) => {
  try {
    const { reason, txHash } = z
      .object({ reason: z.string().trim().min(2).max(500), txHash: zTxHash })
      .strict()
      .parse(req.body);
    const vcId = param(req.params, "vcId");
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await changeStatus(vcId, actor, "revoked", reason, txHash));
  } catch (e) {
    next(e);
  }
});

/** Admin tạm ngưng VC của bất kỳ issuer nào (admin_suspend_vc). */
router.post("/credentials/:vcId/suspend", async (req, res, next) => {
  try {
    const { reason, txHash } = zReasonTx.strict().parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await changeStatus(param(req.params, "vcId"), actor, "suspended", reason, txHash));
  } catch (e) {
    next(e);
  }
});

/**
 * Admin khoá / mở / thu hồi DID của một địa chỉ (admin_suspend_did,
 * admin_reactivate_did, admin_revoke_did). Thu hồi DID thu hồi luôn vai trò.
 */
router.post("/dids/:address/status", async (req, res, next) => {
  try {
    const address = zAddress.parse(param(req.params, "address"));
    const { status, reason, txHash } = zReasonTx
      .extend({ status: z.enum(["suspended", "active", "revoked"]) })
      .strict()
      .parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await authority.moderateDid(actor, address, status, reason, txHash));
  } catch (e) {
    next(e);
  }
});

// ---------------------------------------------------------------------------
// C2/C3/P4.2 (nâng cấp 13/11): xem xét theo lô, nối liên kết cấp lại, chuyển ví.
// ---------------------------------------------------------------------------

/** Mọi VC do một issuer cấp — để xem xét sau khi issuer bị thu hồi. */
router.get("/issuers/:address/credentials", async (req, res, next) => {
  try {
    sendOk(res, await review.listIssuedBy(zAddress.parse(param(req.params, "address"))));
  } catch (e) {
    next(e);
  }
});

/** admin_suspend_vcs / admin_revoke_vcs. */
router.post("/credentials/batch", async (req, res, next) => {
  try {
    const { action, vcIds, reason, txHash } = zBatchBody.parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await review.batchChangeStatus(actor, "admin", action, vcIds, reason, txHash));
  } catch (e) {
    next(e);
  }
});

/** admin_link_replacement: issuer gốc đã mất quyền, issuer khác cấp mới, admin nối. */
router.post("/credentials/:vcId/replacement", async (req, res, next) => {
  try {
    const { newVcId, txHash } = z
      .object({ newVcId: z.string().trim().min(8).max(200), txHash: zTxHash })
      .strict()
      .parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await review.linkReplacement(actor, param(req.params, "vcId"), newVcId, txHash));
  } catch (e) {
    next(e);
  }
});

/** P4.2: ghi liên kết ví cũ → ví mới sau khi đã xác minh danh tính ngoài hệ thống. */
router.post("/identity-migrations", async (req, res, next) => {
  try {
    const { oldAddress, newAddress, note } = z
      .object({ oldAddress: zAddress, newAddress: zAddress, note: z.string().trim().min(2).max(500) })
      .strict()
      .parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await review.recordMigration(actor, oldAddress, newAddress, note), 201);
  } catch (e) {
    next(e);
  }
});

router.get("/identity-migrations/:address", async (req, res, next) => {
  try {
    sendOk(res, await review.migrationOf(zAddress.parse(param(req.params, "address"))));
  } catch (e) {
    next(e);
  }
});

/** Admin kích hoạt lại VC đang tạm ngưng. */
router.post("/credentials/:vcId/reinstate", async (req, res, next) => {
  try {
    const { reason, txHash } = z
      .object({ reason: z.string().trim().min(2).max(500), txHash: zTxHash })
      .strict()
      .parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await changeStatus(param(req.params, "vcId"), actor, "active", reason, txHash));
  } catch (e) {
    next(e);
  }
});

// ===================================================================
// Quản trị quyền hạn TRÊN CHUỖI
//
// Ví phi lưu ký nên chính người dùng ký và gửi giao dịch; backend chỉ xác minh
// giao dịch có thật rồi cập nhật chỉ mục. Màn hình này từng bị hoãn vì contract
// dính F-00 và F-01 — dựng ra cũng chỉ luôn báo lỗi. Cả hai đã sửa.
// ===================================================================

/** Quyền root hiện tại và đề cử đang chờ ký nhận. */
router.get("/authority/root", async (req, res, next) => {
  try {
    sendOk(res, await authority.rootSnapshot(req.user!.address));
  } catch (e) {
    next(e);
  }
});

/** Mọi thứ chuỗi biết về quyền hạn của một địa chỉ. */
router.get("/authority/role/:address", async (req, res, next) => {
  try {
    const address = zAddress.parse(param(req.params, "address"));
    sendOk(res, await authority.roleSnapshot(address));
  } catch (e) {
    next(e);
  }
});

/** Root cấp quyền admin. */
router.post("/authority/admins", async (req, res, next) => {
  try {
    const { address, txHash } = z.object({ address: zAddress, txHash: zTxHash }).strict()
      .parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await authority.grantAdmin(actor, address, txHash), 201);
  } catch (e) {
    next(e);
  }
});

/** Root thu hồi quyền admin. */
router.post("/authority/admins/:address/revoke", async (req, res, next) => {
  try {
    const address = zAddress.parse(param(req.params, "address"));
    const { reason, txHash } = zReasonTx.strict()
      .parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await authority.revokeAdmin(actor, address, reason, txHash));
  } catch (e) {
    next(e);
  }
});

/** Root hoặc admin phê duyệt issuer. */
router.post("/authority/issuers", async (req, res, next) => {
  try {
    const { address, vcTypeMask, expiresAt, txHash } = z
      .object({
        address: zAddress,
        vcTypeMask: z.coerce.number().int().min(1).max(63),
        /** Giây Unix; 0 = vĩnh viễn. */
        expiresAt: z.coerce.number().int().min(0).default(0),
        txHash: zTxHash,
      })
      .strict()
      .parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await authority.approveIssuer(actor, address, vcTypeMask, expiresAt, txHash), 201);
  } catch (e) {
    next(e);
  }
});

/** Tạm ngưng / kích hoạt lại / thu hồi quyền issuer. */
router.post("/authority/issuers/:address/status", async (req, res, next) => {
  try {
    const address = zAddress.parse(param(req.params, "address"));
    const { status, reason, txHash } = zReasonTx
      .extend({ status: z.enum(["suspended", "active", "revoked"]) })
      .strict()
      .parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await authority.setIssuerStatus(actor, address, status, reason, txHash));
  } catch (e) {
    next(e);
  }
});

/** Bước 1 của chuyển quyền root: đề cử. */
router.post("/authority/root/propose", async (req, res, next) => {
  try {
    const { address, txHash } = z.object({ address: zAddress, txHash: zTxHash }).strict()
      .parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await authority.proposeRoot(actor, address, txHash));
  } catch (e) {
    next(e);
  }
});

/** Root huỷ đề cử đang chờ. */
router.post("/authority/root/cancel", async (req, res, next) => {
  try {
    const { txHash } = z.object({ txHash: zTxHash }).strict()
      .parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await authority.cancelRootTransfer(actor, txHash));
  } catch (e) {
    next(e);
  }
});

router.get("/audit", async (req, res, next) => {
  try {
    const { limit, offset } = zPagination.parse(req.query);
    sendOk(
      res,
      await query("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT $1 OFFSET $2", [
        limit,
        offset,
      ]),
    );
  } catch (e) {
    next(e);
  }
});

export default router;
