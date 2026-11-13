import { randomUUID, randomBytes } from "node:crypto";
import jwt from "jsonwebtoken";
import { cfg } from "../config/index.js";
import { query, queryOne } from "../db/pool.js";
import { unauthorized } from "../utils/errors.js";
import { verifyEd25519 } from "../utils/ed25519.js";
import type { EntityRow, JwtPayload } from "../types/index.js";

const CHALLENGE_TTL_MS = 5 * 60_000;

/**
 * Thông điệp được ký. Ràng buộc rõ mục đích, địa chỉ và nonce để chữ ký
 * của phiên này không thể tái sử dụng ở nơi khác (chống replay chéo ngữ cảnh).
 */
export function challengeMessage(address: string, nonce: string): string {
  return [
    "VNU-Trust xac thuc dang nhap",
    `dia chi: ${address}`,
    `nonce: ${nonce}`,
  ].join("\n");
}

export interface ChallengeResult {
  nonce: string;
  message: string;
  expiresAt: string;
}

export async function createChallenge(address: string): Promise<ChallengeResult> {
  // Chỉ phát challenge cho địa chỉ đã đăng ký — tránh để kẻ lạ dò địa chỉ.
  const entity = await queryOne<EntityRow>("SELECT * FROM entities WHERE address = $1", [address]);
  if (!entity) throw unauthorized("Tài khoản chưa đăng ký trong hệ thống");

  const nonce = randomUUID() + "." + randomBytes(16).toString("hex");
  const expiresAt = new Date(Date.now() + CHALLENGE_TTL_MS);

  await query(
    "INSERT INTO auth_challenges (address, nonce, expires_at) VALUES ($1, $2, $3)",
    [address, nonce, expiresAt],
  );

  return { nonce, message: challengeMessage(address, nonce), expiresAt: expiresAt.toISOString() };
}

/**
 * Xác minh chữ ký Ed25519 trên challenge và cấp JWT.
 *
 * Backend không bao giờ biết khoá riêng: trình duyệt giữ khoá, ký chuỗi
 * challenge rồi gửi lên chữ ký. Ở đây chỉ kiểm tra bằng khoá công khai
 * đã đăng ký.
 */
export async function verifyChallenge(
  address: string,
  nonce: string,
  signature: string,
): Promise<{ token: string; entity: EntityRow }> {
  // Lấy challenge còn hiệu lực VÀ đánh dấu đã dùng trong CÙNG một câu lệnh.
  // Nếu tách thành SELECT rồi UPDATE thì hai yêu cầu song song có thể cùng đọc
  // được một nonce chưa dùng và cùng vượt qua — đây là lỗ hổng dùng lại chữ ký.
  const challenge = await queryOne<{ address: string }>(
    `UPDATE auth_challenges SET used = TRUE
      WHERE nonce = $1 AND used = FALSE AND expires_at > now()
      RETURNING address`,
    [nonce],
  );
  if (!challenge) throw unauthorized("Challenge không tồn tại, đã dùng hoặc đã hết hạn");
  if (challenge.address !== address) throw unauthorized("Challenge không thuộc về địa chỉ này");

  const entity = await queryOne<EntityRow>("SELECT * FROM entities WHERE address = $1", [address]);
  if (!entity) throw unauthorized("Tài khoản chưa đăng ký trong hệ thống");

  const valid = verifyEd25519(entity.public_key_hex, challengeMessage(address, nonce), signature);
  if (!valid) throw unauthorized("Chữ ký không hợp lệ");

  const payload: JwtPayload = { address: entity.address, did: entity.did, role: entity.role };
  const token = jwt.sign(payload, cfg.JWT_SECRET, {
    algorithm: "HS256",
    expiresIn: cfg.JWT_EXPIRY as jwt.SignOptions["expiresIn"],
  });

  return { token, entity };
}

export function verifyToken(token: string): JwtPayload {
  try {
    // Ghim thuật toán: không ghim thì jsonwebtoken nhận cả HS384/HS512 ký bằng cùng
    // khoá, trong khi bản Go chỉ nhận HS256 — hai backend lệch nhau (L-01).
    return jwt.verify(token, cfg.JWT_SECRET, { algorithms: ["HS256"] }) as JwtPayload;
  } catch {
    throw unauthorized("Token không hợp lệ hoặc đã hết hạn");
  }
}

/** Dọn challenge hết hạn — gọi định kỳ để bảng không phình vô hạn. */
export async function purgeExpiredChallenges(): Promise<number> {
  const rows = await query<{ count: string }>(
    "WITH d AS (DELETE FROM auth_challenges WHERE expires_at < now() - interval '1 day' RETURNING 1) SELECT count(*)::text AS count FROM d",
  );
  return Number(rows[0]?.count ?? 0);
}
