import "dotenv/config";
import { z } from "zod";

/**
 * Cấu hình được kiểm tra ngay lúc khởi động. Thiếu biến bắt buộc thì
 * tiến trình dừng ngay thay vì chết giữa chừng khi đã nhận request.
 */
const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
  PORT: z.coerce.number().int().positive().default(4000),
  FRONTEND_ORIGIN: z.string().default("http://localhost:5173"),

  DB_HOST: z.string().default("localhost"),
  DB_PORT: z.coerce.number().int().positive().default(5432),
  DB_NAME: z.string().default("vnu_trust"),
  DB_USER: z.string().default("vnu_trust"),
  DB_PASSWORD: z.string().default("vnu_trust"),
  DB_POOL_MAX: z.coerce.number().int().positive().default(10),

  // Tối thiểu 32 ký tự — chặn việc vô tình chạy production với secret rác.
  JWT_SECRET: z.string().min(32, "JWT_SECRET phải dài ít nhất 32 ký tự"),
  JWT_EXPIRY: z.string().default("8h"),

  CHAIN_FULLNODE: z.string().url().default("https://testnet.movementnetwork.xyz/v1"),
  CHAIN_ID: z.coerce.number().int().default(250),
  CONTRACT_ADDRESS: z.string().regex(/^0x[0-9a-fA-F]{1,64}$/, "CONTRACT_ADDRESS không hợp lệ"),
  /** Bật xác minh giao dịch on-chain trước khi ghi DB. Chỉ tắt khi chạy test. */
  VERIFY_ONCHAIN: z
    .enum(["true", "false"])
    .default("true")
    .transform((v) => v === "true"),

  /** Hạn mức chung mỗi IP mỗi phút. Tách ra cấu hình để đo hiệu năng được
   *  mà không phải sửa mã, và để chỉnh theo tải thật lúc triển khai. */
  RATE_LIMIT_PER_MIN: z.coerce.number().int().positive().default(300),
  /** Hạn mức riêng cho tuyến đăng nhập — chặt hơn vì đây là chỗ bị dò. */
  AUTH_RATE_LIMIT_PER_MIN: z.coerce.number().int().positive().default(20),

  IPFS_PROVIDER: z.enum(["pinata", "mock"]).default("mock"),
  PINATA_JWT: z.string().optional(),
  IPFS_GATEWAY: z.string().default("https://ipfs.io/ipfs"),

  DID_METHOD: z.string().default("did:vnu"),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace"]).default("info"),
});

const parsed = schema.safeParse(process.env);
if (!parsed.success) {
  const lines = parsed.error.issues.map((i) => `  - ${i.path.join(".")}: ${i.message}`);
  console.error("Cấu hình môi trường không hợp lệ:\n" + lines.join("\n"));
  process.exit(1);
}

export const cfg = parsed.data;
export type Config = typeof cfg;

// VERIFY_ONCHAIN=false bỏ qua xác minh giao dịch VÀ đọc quyền từ CSDL thay vì
// chuỗi — ai gọi API cũng tự khai được vai trò. Chỉ dùng để phát triển/kiểm thử;
// chạy thật với cờ này là mở toang hệ thống, nên chặn ngay lúc khởi động.
if (!cfg.VERIFY_ONCHAIN && cfg.NODE_ENV === "production") {
  console.error(
    "VERIFY_ONCHAIN=false không được phép khi NODE_ENV=production — " +
      "cờ này tắt toàn bộ kiểm chứng on-chain.",
  );
  process.exit(1);
}

if (cfg.IPFS_PROVIDER === "pinata" && !cfg.PINATA_JWT) {
  console.error("IPFS_PROVIDER=pinata nhưng thiếu PINATA_JWT");
  process.exit(1);
}
