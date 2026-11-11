import { z } from "zod";

/** Địa chỉ ví: 0x + 1..64 hex. Chuẩn hoá về chữ thường ngay tại tầng nhập. */
export const zAddress = z
  .string()
  .trim()
  .regex(/^0x[0-9a-fA-F]{1,64}$/, "Địa chỉ ví không hợp lệ")
  .transform((v) => v.toLowerCase());

/** Hash 32 byte dạng hex, có hoặc không có tiền tố 0x. */
export const zHash32 = z
  .string()
  .trim()
  .regex(/^(0x)?[0-9a-fA-F]{64}$/, "Hash phải là 32 byte (64 ký tự hex)")
  .transform((v) => (v.startsWith("0x") ? v.toLowerCase() : "0x" + v.toLowerCase()));

export const zTxHash = z
  .string()
  .trim()
  .regex(/^0x[0-9a-fA-F]{64}$/, "txHash phải là 0x + 64 ký tự hex")
  .transform((v) => v.toLowerCase());

/** Khoá công khai Ed25519: 32 byte hex. */
export const zPublicKey = z
  .string()
  .trim()
  .regex(/^(0x)?[0-9a-fA-F]{64}$/, "Khoá công khai Ed25519 phải là 32 byte")
  .transform((v) => (v.startsWith("0x") ? v.toLowerCase() : "0x" + v.toLowerCase()));

/** Chữ ký Ed25519: 64 byte hex. */
export const zSignature = z
  .string()
  .trim()
  .regex(/^(0x)?[0-9a-fA-F]{128}$/, "Chữ ký Ed25519 phải là 64 byte")
  .transform((v) => (v.startsWith("0x") ? v.toLowerCase() : "0x" + v.toLowerCase()));

/**
 * CID của IPFS. Chấp nhận CIDv0 (Qm...) và CIDv1 (bafy/bafk...).
 * Contract hiện KHÔNG kiểm tra CID rỗng (xem F-06 trong CONTRACT_AUDIT.md),
 * nên backend phải chặn ở đây.
 */
export const zCid = z
  .string()
  .trim()
  .min(1, "CID không được rỗng")
  .regex(/^(Qm[1-9A-HJ-NP-Za-km-z]{44}|b[a-z2-7]{58,})$/, "CID không đúng định dạng IPFS");

export const zDid = z
  .string()
  .trim()
  .min(1)
  .max(256)
  .regex(/^did:[a-z0-9]+:[\w.:%-]+$/i, "DID không đúng định dạng");

export const zRole = z.enum(["root", "admin", "issuer", "holder", "verifier"]);

/** Bit mask vc_type hợp lệ: 1..63 (6 bit đã định nghĩa trong constants.move). */
export const zVcType = z.coerce.number().int().min(1).max(63);

export const zPagination = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  offset: z.coerce.number().int().min(0).default(0),
});
