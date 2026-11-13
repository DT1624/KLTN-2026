import { Router } from "express";
import { z } from "zod";
import {
  saveIssuedVc, listByIssuer, requireByVcId, changeStatus, statsByIssuer,
} from "../services/vc.service.js";
import { requireByAddress } from "../services/entity.service.js";
import { requireAuth, requireRole, requireOnChainRole } from "../middleware/auth.js";
import { sendOk, param } from "../utils/http.js";
import { forbidden } from "../utils/errors.js";
import * as authority from "../services/authority.service.js";
import * as review from "../services/review.service.js";
import { zAddress, zCid, zDid, zHash32, zTxHash, zVcType } from "../utils/validate.js";

const router = Router();
router.use(requireAuth, requireRole("issuer"));

/** Thân yêu cầu ghi một VC vừa lên chuỗi — dùng chung cho cấp mới và cấp lại (C3). */
const zIssueBody = z
  .object({
    vcId: z.string().trim().min(8).max(200),
    onChainVcId: z.coerce.number().int().min(0),
    holderDid: zDid,
    holderAddress: zAddress,
    vcType: zVcType,
    ipfsCid: zCid,
    vcIdHash: zHash32,
    contentHash: zHash32,
    proofValue: z.string().trim().min(16),
    // P3: KHÔNG còn vcJson — nội dung nằm trong phong bì mã hoá tại ipfsCid.
    issuedAt: z.string().datetime(),
    expiresAt: z.string().datetime().nullable().default(null),
    txHash: zTxHash,
  })
  .strict();

/** Thân yêu cầu của thao tác theo lô (C2) — giống hệt tuyến admin. */
export const zBatchBody = z
  .object({
    action: z.enum(["suspend", "revoke"]),
    vcIds: z.array(z.string().trim().min(8).max(200)).min(1).max(100),
    reason: z.string().trim().min(2).max(500),
    txHash: zTxHash,
  })
  .strict();

router.get("/stats", async (req, res, next) => {
  try {
    sendOk(res, await statsByIssuer(req.user!.did));
  } catch (e) {
    next(e);
  }
});

router.get("/credentials", async (req, res, next) => {
  try {
    const status = z
      .enum(["active", "suspended", "expired", "revoked"])
      .optional()
      .parse(req.query.status);
    sendOk(res, await listByIssuer(req.user!.did, status));
  } catch (e) {
    next(e);
  }
});

router.get("/credentials/:vcId", async (req, res, next) => {
  try {
    const vc = await requireByVcId(param(req.params, "vcId"));
    if (vc.issuer_did !== req.user!.did) throw forbidden("VC này không do bạn cấp");
    sendOk(res, vc);
  } catch (e) {
    next(e);
  }
});

/** Cấp VC — bắt buộc quyền issuer còn hiệu lực trên chuỗi. */
router.post("/credentials", requireOnChainRole("issuer"), async (req, res, next) => {
  try {
    const body = zIssueBody.parse(req.body);
    const issuer = await requireByAddress(req.user!.address);
    sendOk(res, await saveIssuedVc({ issuer, ...body }), 201);
  } catch (e) {
    next(e);
  }
});

/**
 * Cấp lại văn bằng (reissue_vc, C3): cấp mới + thu hồi văn bằng cũ với lý do
 * "replaced" + ghi liên kết, trong một giao dịch. Người gọi là issuer gốc hoặc
 * issuer cha; đổi sang ví mới khi holder cũ đã bị khoá/thu hồi DID (P4.2).
 */
router.post("/credentials/:vcId/reissue", requireOnChainRole("issuer"), async (req, res, next) => {
  try {
    const body = zIssueBody.parse(req.body);
    const issuer = await requireByAddress(req.user!.address);
    sendOk(res, await review.reissueVc(param(req.params, "vcId"), { issuer, ...body }), 201);
  } catch (e) {
    next(e);
  }
});

/**
 * Ví mới của holder (nếu admin đã ghi nhận chuyển danh tính) — chỉ cho issuer đã
 * cấp văn bằng cho ví cũ: mối nối hai ví là thông tin cá nhân.
 */
router.get("/holders/:address/migration", async (req, res, next) => {
  try {
    const address = zAddress.parse(param(req.params, "address"));
    const actor = await requireByAddress(req.user!.address);
    if (!(await review.issuedToHolder(actor.address, address))) {
      throw forbidden("Bạn chưa cấp văn bằng nào cho ví này");
    }
    sendOk(res, await review.migrationOf(address));
  } catch (e) {
    next(e);
  }
});

router.post("/credentials/:vcId/revoke", async (req, res, next) => {
  try {
    const { reason, txHash } = z
      .object({ reason: z.string().trim().min(2).max(500), txHash: zTxHash })
      .strict()
      .parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await changeStatus(param(req.params, "vcId"), actor, "revoked", reason, txHash));
  } catch (e) {
    next(e);
  }
});

router.post("/credentials/:vcId/suspend", async (req, res, next) => {
  try {
    const { reason, txHash } = z
      .object({ reason: z.string().trim().min(2).max(500), txHash: zTxHash })
      .strict()
      .parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await changeStatus(param(req.params, "vcId"), actor, "suspended", reason, txHash));
  } catch (e) {
    next(e);
  }
});

// ---------------------------------------------------------------------------
// Uỷ quyền: issuer có bit VC_DELEGATION cấp và quản lý sub-issuer.
// Contract quyết định toàn bộ luật; backend xác minh giao dịch rồi ghi chỉ mục.
// ---------------------------------------------------------------------------

/** Quyền uỷ quyền của chính mình và danh sách sub-issuer mình đã cấp. */
router.get("/delegation", async (req, res, next) => {
  try {
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await authority.delegationSnapshot(actor));
  } catch (e) {
    next(e);
  }
});

/** Cấp sub-issuer qua uỷ quyền (approve_issuer do issuer ký). */
router.post("/sub-issuers", async (req, res, next) => {
  try {
    const { address, vcTypeMask, expiresAt, txHash } = z
      .object({
        address: zAddress,
        vcTypeMask: z.coerce.number().int().min(1).max(31),
        /** Giây Unix; 0 = vĩnh viễn (chỉ khi chính mình vĩnh viễn). */
        expiresAt: z.coerce.number().int().min(0).default(0),
        txHash: zTxHash,
      })
      .strict()
      .parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await authority.approveSubIssuer(actor, address, vcTypeMask, expiresAt, txHash), 201);
  } catch (e) {
    next(e);
  }
});

/** Tạm ngưng / thu hồi sub-issuer do chính mình cấp. Kích hoạt lại thì nhờ admin. */
router.post("/sub-issuers/:address/status", async (req, res, next) => {
  try {
    const address = zAddress.parse(param(req.params, "address"));
    const { status, reason, txHash } = z
      .object({
        status: z.enum(["suspended", "revoked"]),
        reason: z.string().trim().min(2).max(500),
        txHash: zTxHash,
      })
      .strict()
      .parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await authority.setSubIssuerStatus(actor, address, status, reason, txHash));
  } catch (e) {
    next(e);
  }
});

// ---------------------------------------------------------------------------
// C2: issuer cha xem xét văn bằng do sub-issuer của mình cấp.
// ---------------------------------------------------------------------------

router.get("/review/:address/credentials", async (req, res, next) => {
  try {
    const address = zAddress.parse(param(req.params, "address"));
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await review.listSubIssuerVcs(actor, address));
  } catch (e) {
    next(e);
  }
});

/** delegator_suspend_vcs / delegator_revoke_vcs. Kích hoạt lại vẫn chỉ admin. */
router.post("/review/batch", async (req, res, next) => {
  try {
    const { action, vcIds, reason, txHash } = zBatchBody.parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await review.batchChangeStatus(actor, "parent", action, vcIds, reason, txHash));
  } catch (e) {
    next(e);
  }
});

export default router;
