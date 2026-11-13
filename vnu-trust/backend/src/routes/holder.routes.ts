import { Router } from "express";
import { z } from "zod";
import { listByHolder, requireByVcId, effectiveStatus, effectiveStatuses } from "../services/vc.service.js";
import {
  createPresentation, listByHolder as listVps, listShareTokens, revokeShareToken,
} from "../services/vp.service.js";
import { requireByAddress } from "../services/entity.service.js";
import { requireAuth, requireRole } from "../middleware/auth.js";
import { sendOk, param } from "../utils/http.js";
import { forbidden } from "../utils/errors.js";
import { zCid, zDid, zHash32 } from "../utils/validate.js";

const router = Router();
router.use(requireAuth, requireRole("holder"));

/** Ví chứng chỉ của người sở hữu, kèm trạng thái hiệu lực thật. */
router.get("/credentials", async (req, res, next) => {
  try {
    const rows = await listByHolder(req.user!.did);
    // P5: một lần đọc lô thay cho N lần get_vc_status.
    const eff = await effectiveStatuses(rows);
    sendOk(res, rows.map((vc) => ({ ...vc, effective: eff.get(vc.vc_id) })));
  } catch (e) {
    next(e);
  }
});

router.get("/credentials/:vcId", async (req, res, next) => {
  try {
    const vc = await requireByVcId(param(req.params, "vcId"));
    if (vc.holder_did !== req.user!.did) throw forbidden("VC này không thuộc về bạn");
    sendOk(res, { ...vc, effective: await effectiveStatus(vc) });
  } catch (e) {
    next(e);
  }
});

router.get("/presentations", async (req, res, next) => {
  try {
    sendOk(res, await listVps(req.user!.did));
  } catch (e) {
    next(e);
  }
});

/** Tạo VP + liên kết chia sẻ có hạn. */
router.post("/presentations", async (req, res, next) => {
  try {
    const body = z
      .object({
        vpId: z.string().trim().min(8).max(200),
        verifierDid: zDid.nullable().default(null),
        vcIds: z.array(z.string().trim().min(8)).min(1).max(20),
        ipfsCid: zCid,
        vpHash: zHash32,
        proofValue: z.string().trim().min(16),
        challenge: z.string().trim().max(200).nullable().default(null),
        ttlSeconds: z.coerce.number().int().min(60).max(604800).default(3600),
      })
      .strict()
      .parse(req.body);
    const holder = await requireByAddress(req.user!.address);
    const { vp, share } = await createPresentation({ holder, ...body });
    sendOk(res, { vp, share: { token: share.token, expiresAt: share.expires_at } }, 201);
  } catch (e) {
    next(e);
  }
});

router.get("/shares", async (req, res, next) => {
  try {
    sendOk(res, await listShareTokens(req.user!.did));
  } catch (e) {
    next(e);
  }
});

router.delete("/shares/:token", async (req, res, next) => {
  try {
    await revokeShareToken(param(req.params, "token"), req.user!.did, req.user!.address);
    sendOk(res, { revoked: true });
  } catch (e) {
    next(e);
  }
});

export default router;
