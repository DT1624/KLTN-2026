import { Router } from "express";
import { z } from "zod";
import {
  openShareToken, verifyPresentation, saveVerification, verificationHistory,
} from "../services/vp.service.js";
import { requireAuth, requireRole } from "../middleware/auth.js";
import { sendOk, param } from "../utils/http.js";

const router = Router();

/**
 * Công khai: xem nhanh một liên kết chia sẻ (bên xác minh vừa quét QR,
 * chưa cần đăng nhập). Chỉ trả về siêu dữ liệu, chưa chạy xác minh đầy đủ.
 */
router.get("/share/:token", async (req, res, next) => {
  try {
    sendOk(res, await openShareToken(param(req.params, "token")));
  } catch (e) {
    next(e);
  }
});

/**
 * Thân yêu cầu xác minh (P3): bản trình bày mà TRÌNH DUYỆT người xác minh vừa giải
 * mã bằng khoá trong fragment liên kết. Máy chủ chạy 7 bước trên bản này rồi bỏ đi —
 * không lưu bản rõ, chỉ lưu báo cáo.
 */
const zVerifyBody = z.object({ vp: z.record(z.unknown()) }).strict();

/** Công khai: chạy đủ 7 bước xác minh cho một liên kết chia sẻ. */
router.post("/share/:token", async (req, res, next) => {
  try {
    const { vp } = zVerifyBody.parse(req.body);
    sendOk(res, await verifyPresentation(param(req.params, "token"), vp));
  } catch (e) {
    next(e);
  }
});

/** Có đăng nhập: xác minh rồi lưu lại vào lịch sử của bên xác minh. */
router.post("/share/:token/record", requireAuth, requireRole("verifier", "admin", "root"),
  async (req, res, next) => {
    try {
      const { vp } = zVerifyBody.parse(req.body);
      const report = await verifyPresentation(param(req.params, "token"), vp);
      await saveVerification(report.vpId, req.user!.address, report);
      sendOk(res, report);
    } catch (e) {
      next(e);
    }
  });

router.get("/history", requireAuth, requireRole("verifier", "admin", "root"),
  async (req, res, next) => {
    try {
      const limit = z.coerce.number().int().min(1).max(200).default(50).parse(req.query.limit ?? 50);
      sendOk(res, await verificationHistory(req.user!.address, limit));
    } catch (e) {
      next(e);
    }
  });

export default router;
