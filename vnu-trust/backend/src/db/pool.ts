import pg from "pg";
import { cfg } from "../config/index.js";
import { logger } from "../utils/logger.js";

/**
 * Postgres trả DECIMAL/BIGINT dưới dạng chuỗi để tránh mất chính xác.
 * on_chain_vc_id là BIGINT nhưng luôn nằm trong khoảng an toàn của
 * Number, nên ép về số cho tiện dùng ở tầng trên.
 */
pg.types.setTypeParser(pg.types.builtins.INT8, (v) => Number(v));

export const pool = new pg.Pool({
  host: cfg.DB_HOST,
  port: cfg.DB_PORT,
  database: cfg.DB_NAME,
  user: cfg.DB_USER,
  password: cfg.DB_PASSWORD,
  max: cfg.DB_POOL_MAX,
  ssl: cfg.DB_SSLMODE === "disable" ? false : { rejectUnauthorized: cfg.DB_SSLMODE === "verify-full" },
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
});

pool.on("error", (err) => logger.error({ err }, "Lỗi client Postgres nhàn rỗi"));

export async function query<T extends pg.QueryResultRow>(
  sql: string,
  params: readonly unknown[] = [],
): Promise<T[]> {
  const res = await pool.query<T>(sql, params as unknown[]);
  return res.rows;
}

/** Trả về bản ghi đầu tiên hoặc null — tránh lặp `rows[0] ?? null` khắp nơi. */
export async function queryOne<T extends pg.QueryResultRow>(
  sql: string,
  params: readonly unknown[] = [],
): Promise<T | null> {
  const rows = await query<T>(sql, params);
  return rows[0] ?? null;
}

/** Chạy nhiều câu lệnh trong một giao dịch, tự rollback khi có lỗi. */
export async function withTx<T>(fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  } finally {
    client.release();
  }
}

export async function waitForDb(retries = 20, delayMs = 2000): Promise<void> {
  for (let i = 1; i <= retries; i++) {
    try {
      await pool.query("SELECT 1");
      logger.info("Đã kết nối Postgres");
      return;
    } catch {
      logger.warn(`Postgres chưa sẵn sàng (${i}/${retries}), thử lại sau ${delayMs}ms`);
      await new Promise((r) => setTimeout(r, delayMs));
    }
  }
  throw new Error(`Không kết nối được Postgres sau ${retries} lần thử`);
}
