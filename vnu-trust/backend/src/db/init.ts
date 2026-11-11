import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { pool, waitForDb } from "./pool.js";
import { logger } from "../utils/logger.js";

/** Nạp db/schema.sql — schema này dùng chung cho cả backend Go. */
const here = dirname(fileURLToPath(import.meta.url));
const schemaPath = resolve(here, "../../../db/schema.sql");

async function main() {
  await waitForDb();
  const sql = await readFile(schemaPath, "utf8");
  await pool.query(sql);
  logger.info(`Đã áp dụng lược đồ từ ${schemaPath}`);
  await pool.end();
}

main().catch((e) => {
  logger.error({ err: e }, "Khởi tạo CSDL thất bại");
  process.exit(1);
});
