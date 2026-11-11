import { Router } from "express";
import { z } from "zod";
import { requireAuth } from "../middleware/auth.js";
import { requireByAddress } from "../services/entity.service.js";
import * as authority from "../services/authority.service.js";
import { sendOk } from "../utils/http.js";
import { zTxHash } from "../utils/validate.js";

/**
 * Tuyến quản trị quyền KHÔNG đòi vai trò admin.
 *
 * Lý do tồn tại riêng: người được đề cử làm root, tại thời điểm ký nhận, vẫn
 * chưa phải root trong CSDL — nếu đặt tuyến này dưới `/admin` (vốn chặn theo
 * vai trò admin/root) thì họ sẽ bị 403 ngay ở bước duy nhất chứng minh được họ
 * giữ khoá. Quyền thật vẫn do contract quyết định: `accept_root` chỉ thành công
 * trên chuỗi nếu người ký đúng là địa chỉ đang được đề cử.
 */
const router = Router();
router.use(requireAuth);

/** Ai đang là root, ai đang được đề cử — công khai với mọi tài khoản đã đăng nhập. */
router.get("/root", async (req, res, next) => {
  try {
    sendOk(res, await authority.rootSnapshot(req.user!.address));
  } catch (e) {
    next(e);
  }
});

/** Bước 2 của chuyển quyền root: người được đề cử tự ký nhận. */
router.post("/root/accept", async (req, res, next) => {
  try {
    const { txHash } = z.object({ txHash: zTxHash }).strict()
      .parse(req.body);
    const actor = await requireByAddress(req.user!.address);
    sendOk(res, await authority.acceptRoot(actor, txHash));
  } catch (e) {
    next(e);
  }
});

export default router;
