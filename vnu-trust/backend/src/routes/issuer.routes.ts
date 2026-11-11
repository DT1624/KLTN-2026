import { Router } from "express";
import { z } from "zod";
import {
  saveIssuedVc, listByIssuer, requireByVcId, changeStatus, statsByIssuer,
} from "../services/vc.service.js";
import { requireByAddress } from "../services/entity.service.js";
import { requireAuth, requireRole, requireOnChainRole } from "../middleware/auth.js";
import { sendOk, param } from "../utils/http.js";
import { forbidden } from "../utils/errors.js";
import { zAddress, zCid, zDid, zHash32, zTxHash, zVcType } from "../utils/validate.js";

const router = Router();
router.use(requireAuth, requireRole("issuer"));

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
    const body = z
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
        vcJson: z.record(z.unknown()),
        issuedAt: z.string().datetime(),
        expiresAt: z.string().datetime().nullable().default(null),
        txHash: zTxHash,
      })
      .strict()
      .parse(req.body);
    const issuer = await requireByAddress(req.user!.address);
    sendOk(res, await saveIssuedVc({ issuer, ...body }), 201);
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

export default router;
