import { Router } from "express";
import { z } from "zod";
import { lookup } from "../services/resolver.service.js";
import { pinJSON, canonicalize } from "../services/ipfs.service.js";
import { AppError } from "../utils/errors.js";

/** Giới hạn một lần ghim — khớp maxPinBytes bên Go. */
const MAX_PIN_BYTES = 256 * 1024;
import { requireAuth } from "../middleware/auth.js";
import { sendOk } from "../utils/http.js";
import { authorityStats, totalDids, totalVcs, getRootAdmin } from "../chain/registry.js";
import { chainHealth } from "../chain/client.js";
import { cfg } from "../config/index.js";
import { ttlCache } from "../utils/ttl-cache.js";

const router = Router();

/** Ô tra cứu hợp nhất: DID, địa chỉ ví, CID, mã VC hoặc mã giao dịch. */
router.get("/lookup", async (req, res, next) => {
  try {
    const q = z.string().trim().min(3).max(300).parse(req.query.q);
    sendOk(res, await lookup(q));
  } catch (e) {
    next(e);
  }
});

/**
 * Số liệu tổng quan cho trang chủ. Đệm 5 giây: đây là bốn phép tổng hợp riêng
 * biệt, ở chế độ on-chain là bốn vòng gọi fullnode cho mỗi lượt xem trang.
 * Bộ đếm chậm vài giây thì không ai thấy, nhưng gọi fullnode dồn dập thì thấy.
 */
const cachedStats = ttlCache(5_000, async () => {
  const [authority, dids, vcs, chain, root] = await Promise.all([
    authorityStats(),
    totalDids(),
    totalVcs(),
    chainHealth(),
    getRootAdmin(),
  ]);
  return {
    admins: authority.admins,
    issuers: authority.issuers,
    dids,
    credentials: vcs,
    chainId: chain.chainId,
    ledgerVersion: chain.ledgerVersion,
    rootAdmin: root,
    contract: cfg.CONTRACT_ADDRESS,
  };
});

router.get("/stats", async (_req, res, next) => {
  try {
    sendOk(res, await cachedStats());
  } catch (e) {
    next(e);
  }
});

/** Ghim JSON lên IPFS — cần đăng nhập để tránh bị lạm dụng làm kho lưu trữ. */
router.post("/ipfs/pin", requireAuth, async (req, res, next) => {
  try {
    const { json, name } = z
      .object({ json: z.record(z.unknown()), name: z.string().trim().min(1).max(120) })
      .strict()
      .parse(req.body);
    // Văn bằng/DID Document thật chỉ vài KB. Không giới hạn thì ai tự đăng ký được
    // tài khoản holder đều ghim được ~2 MB mỗi yêu cầu vào ipfs_objects (S-07).
    const size = Buffer.byteLength(canonicalize(json));
    if (size > MAX_PIN_BYTES) {
      throw new AppError(413, `Nội dung ghim ${size} byte, vượt giới hạn ${MAX_PIN_BYTES} byte`, "PAYLOAD_TOO_LARGE");
    }
    sendOk(res, await pinJSON(json, name), 201);
  } catch (e) {
    next(e);
  }
});

export default router;
