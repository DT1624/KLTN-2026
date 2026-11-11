import { Router } from "express";
import { z } from "zod";
import { registerEntity, getByAddress } from "../services/entity.service.js";
import { sendOk, param } from "../utils/http.js";
import { notFound } from "../utils/errors.js";
import { zAddress, zPublicKey, zDid, zRole } from "../utils/validate.js";

/**
 * Lưu ý về `.strict()` dùng ở mọi schema thân yêu cầu trong thư mục này:
 * zod mặc định BỎ QUA trường lạ, còn `encoding/json` bên Go (bật DisallowUnknownFields)
 * thì TỪ CHỐI. Cùng một yêu cầu cho hai mã trạng thái khác nhau — đúng loại lệch
 * mà bộ đối chiếu parity sinh ra để bắt. Hai bên nay đều nghiêm ngặt, và nghiêm
 * ngặt là phía đúng: gõ nhầm `expireAt` thay vì `expiresAt` phải báo lỗi ngay,
 * chứ không phải lặng lẽ cấp một văn bằng vĩnh viễn.
 */
const router = Router();

router.post("/register", async (req, res, next) => {
  try {
    const body = z
      .object({
        address: zAddress,
        publicKeyHex: zPublicKey,
        did: zDid,
        role: zRole,
        label: z.string().trim().min(2).max(120),
        email: z.string().email().optional(),
      })
      .strict()
      .parse(req.body);
    sendOk(res, await registerEntity(body), 201);
  } catch (e) {
    next(e);
  }
});

router.get("/by-address/:address", async (req, res, next) => {
  try {
    const address = zAddress.parse(param(req.params, "address"));
    const entity = await getByAddress(address);
    if (!entity) throw notFound("Không tìm thấy thực thể");
    // Không lộ email ra tuyến công khai (giữ khoá, đặt null — giống bản Go).
    sendOk(res, { ...entity, email: null });
  } catch (e) {
    next(e);
  }
});

export default router;
