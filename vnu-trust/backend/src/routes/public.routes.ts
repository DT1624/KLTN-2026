import { Router } from "express";
import { z } from "zod";
import { lookup } from "../services/resolver.service.js";
import { pinJSON } from "../services/ipfs.service.js";
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
    sendOk(res, await pinJSON(json, name), 201);
  } catch (e) {
    next(e);
  }
});

export default router;
