import { Router } from "express";
import { z } from "zod";
import { saveDid, resolve, resolveByAddress } from "../services/did.service.js";
import { requireByAddress } from "../services/entity.service.js";
import { requireAuth } from "../middleware/auth.js";
import { selfDidStatus } from "../services/review.service.js";
import { sendOk, param } from "../utils/http.js";
import { zDid, zCid, zHash32, zTxHash, zAddress } from "../utils/validate.js";

const router = Router();

/** Công khai — ai cũng resolve được DID, đúng tinh thần sổ đăng ký mở. */
router.get("/resolve", async (req, res, next) => {
  try {
    const did = zDid.parse(req.query.did);
    sendOk(res, await resolve(did));
  } catch (e) {
    next(e);
  }
});

router.get("/by-address/:address", async (req, res, next) => {
  try {
    sendOk(res, await resolveByAddress(zAddress.parse(param(req.params, "address"))));
  } catch (e) {
    next(e);
  }
});

/** Ghi nhận DID sau khi giao dịch register_did đã lên chuỗi. */
router.post("/save", requireAuth, async (req, res, next) => {
  try {
    const body = z
      .object({
        did: zDid,
        documentCid: zCid,
        documentHash: zHash32,
        docJson: z.record(z.unknown()),
        txHash: zTxHash,
      })
      .strict()
      .parse(req.body);
    const entity = await requireByAddress(req.user!.address);
    sendOk(res, await saveDid({ entity, ...body }), 201);
  } catch (e) {
    next(e);
  }
});

/** P4.1: chủ DID tự khoá (suspend_own_did) / tự mở (reactivate_own_did). */
router.post("/self-status", requireAuth, async (req, res, next) => {
  try {
    const { status, txHash } = z
      .object({ status: z.enum(["suspended", "active"]), txHash: zTxHash })
      .strict()
      .parse(req.body);
    const entity = await requireByAddress(req.user!.address);
    sendOk(res, await selfDidStatus(entity, status, txHash));
  } catch (e) {
    next(e);
  }
});

export default router;
