import { createApp } from "./app.js";
import { cfg } from "./config/index.js";
import { logger } from "./utils/logger.js";
import { waitForDb, pool } from "./db/pool.js";
import { chainHealth } from "./chain/client.js";
import { purgeExpiredChallenges } from "./services/auth.service.js";

async function main() {
  await waitForDb();

  try {
    const chain = await chainHealth();
    logger.info({ ...chain, contract: cfg.CONTRACT_ADDRESS }, "Đã kết nối fullnode");
  } catch (e) {
    // Không chặn khởi động: các tuyến công khai không phụ thuộc chuỗi vẫn chạy được.
    logger.error({ err: e }, "Không kết nối được fullnode — các tính năng on-chain sẽ lỗi");
  }

  const app = createApp();
  const server = app.listen(cfg.PORT, () => {
    logger.info(`VNU-Trust backend đang chạy tại http://localhost:${cfg.PORT}`);
  });

  const purgeTimer = setInterval(
    () => purgeExpiredChallenges().catch((e) => logger.warn({ err: e }, "Dọn challenge lỗi")),
    60 * 60_000,
  );

  const shutdown = (sig: string) => {
    logger.info(`Nhận ${sig}, đang dừng...`);
    clearInterval(purgeTimer);
    server.close(() => {
      pool.end().finally(() => process.exit(0));
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

main().catch((e) => {
  logger.fatal({ err: e }, "Khởi động thất bại");
  process.exit(1);
});
