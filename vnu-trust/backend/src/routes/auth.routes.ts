import { Router } from "express";
import { z } from "zod";
import rateLimit from "express-rate-limit";
import { cfg } from "../config/index.js";
import { createChallenge, verifyChallenge } from "../services/auth.service.js";
import { requireAuth } from "../middleware/auth.js";
import { getLiveStatus } from "../services/entity.service.js";
import { sendOk, fail } from "../utils/http.js";
import { zAddress, zSignature } from "../utils/validate.js";

const router = Router();

/** Giới hạn tần suất để chặn dò địa chỉ và thử chữ ký hàng loạt. */
const authLimiter = rateLimit({
  windowMs: 60_000,
  limit: cfg.AUTH_RATE_LIMIT_PER_MIN,
  standardHeaders: true,
  legacyHeaders: false,
  // Đủ phong bì JSON (data, timestamp) như bản Go — P-08.
  handler: (_req, res) => { res.status(429).json(fail("Quá nhiều yêu cầu, thử lại sau một phút")); },
});

router.post("/challenge", authLimiter, async (req, res, next) => {
  try {
    const { address } = z.object({ address: zAddress }).strict()
      .parse(req.body);
    sendOk(res, await createChallenge(address));
  } catch (e) {
    next(e);
  }
});

router.post("/verify", authLimiter, async (req, res, next) => {
  try {
    const body = z
      .object({ address: zAddress, nonce: z.string().min(8), signature: zSignature })
      .strict()
      .parse(req.body);
    const { token, entity } = await verifyChallenge(body.address, body.nonce, body.signature);
    sendOk(res, {
      token,
      entity: {
        address: entity.address,
        did: entity.did,
        role: entity.role,
        label: entity.label,
      },
    });
  } catch (e) {
    next(e);
  }
});

/** Hồ sơ phiên hiện tại, kèm đối chiếu quyền thật trên chuỗi. */
router.get("/me", requireAuth, async (req, res, next) => {
  try {
    sendOk(res, await getLiveStatus(req.user!.address));
  } catch (e) {
    next(e);
  }
});

export default router;
