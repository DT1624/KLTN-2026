import { query, queryOne } from "../db/pool.js";
import { conflict, notFound, badRequest, forbidden } from "../utils/errors.js";
import { cfg } from "../config/index.js";
import { hasActiveDid, isActiveAdmin, isActiveIssuer, canDelegate } from "../chain/registry.js";
import { OFFLINE } from "../chain/offline.js";
import type { EntityRow, Role } from "../types/index.js";
import { createHash } from "node:crypto";

/** Địa chỉ Aptos/Movement của khoá Ed25519 một chữ ký: SHA3-256(pub ‖ 0x00). */
export function deriveAddress(publicKeyHex: string): string {
  const pub = Buffer.from(publicKeyHex.replace(/^0x/, ""), "hex");
  return "0x" + createHash("sha3-256").update(Buffer.concat([pub, Buffer.from([0])])).digest("hex");
}

export interface RegisterEntityInput {
  address: string;
  publicKeyHex: string;
  did: string;
  role: Role;
  label: string;
  email?: string;
}

/**
 * Đăng ký thực thể — chỉ là ghi danh phía ứng dụng, quyền thật nằm trên chuỗi.
 * Ở chế độ nghiêm ngặt, vai trò admin/issuer phải được chuỗi công nhận trước:
 * nếu không, ai cũng tự khai admin để đọc văn bằng và nhật ký của người khác.
 */
export async function registerEntity(input: RegisterEntityInput): Promise<EntityRow> {
  if (input.role === "root") {
    throw badRequest("Không thể tự đăng ký vai trò root — root do contract quy định lúc publish");
  }

  // Địa chỉ phải là địa chỉ của CHÍNH khoá công khai được khai (S-01). Thiếu
  // bước này thì ai cũng ghi danh được địa chỉ của người khác — kể cả admin hay
  // root trên chuỗi chưa ghi danh — bằng khoá của mình, rồi ký challenge mà đăng nhập.
  if (deriveAddress(input.publicKeyHex) !== input.address) {
    throw badRequest("Địa chỉ ví không khớp khoá công khai (địa chỉ = SHA3-256(khoá công khai ‖ 0x00))");
  }

  // DID phải bám theo địa chỉ ví để không thể mạo danh DID của người khác.
  const expectedPrefix = `${cfg.DID_METHOD}:${input.role}:`;
  if (!input.did.startsWith(expectedPrefix) || !input.did.endsWith(input.address)) {
    throw badRequest(`DID phải có dạng ${expectedPrefix}<địa chỉ ví>`);
  }

  const existing = await queryOne<EntityRow>(
    "SELECT * FROM entities WHERE address = $1 OR did = $2",
    [input.address, input.did],
  );
  if (existing) {
    throw conflict(
      existing.address === input.address
        ? "Địa chỉ ví này đã được đăng ký"
        : "DID này đã được đăng ký",
    );
  }

  if (!OFFLINE && (input.role === "admin" || input.role === "issuer")) {
    const ok = input.role === "admin"
      ? await isActiveAdmin(input.address)
      : await isActiveIssuer(input.address);
    if (!ok) {
      throw forbidden(
        `Địa chỉ này chưa được cấp quyền ${input.role} trên chuỗi — hãy đăng ký với vai trò holder, ` +
          "vai trò sẽ tự nâng khi được cấp quyền",
      );
    }
  }

  const row = await queryOne<EntityRow>(
    `INSERT INTO entities (address, public_key_hex, did, role, label, email)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [input.address, input.publicKeyHex, input.did, input.role, input.label, input.email ?? null],
  );
  if (!row) throw new Error("Chèn entity thất bại");
  return row;
}

export async function getByAddress(address: string): Promise<EntityRow | null> {
  return queryOne<EntityRow>("SELECT * FROM entities WHERE address = $1", [address]);
}

export async function getByDid(did: string): Promise<EntityRow | null> {
  return queryOne<EntityRow>("SELECT * FROM entities WHERE did = $1", [did]);
}

export async function requireByAddress(address: string): Promise<EntityRow> {
  const e = await getByAddress(address);
  if (!e) throw notFound("Không tìm thấy thực thể");
  return e;
}

export async function listByRole(role: Role, limit = 50, offset = 0): Promise<EntityRow[]> {
  return query<EntityRow>(
    "SELECT * FROM entities WHERE role = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
    [role, limit, offset],
  );
}

/**
 * Trạng thái thực tế của một thực thể, đối chiếu giữa CSDL và chuỗi.
 * Dùng cho màn hình hồ sơ để người dùng thấy ngay nếu ứng dụng và chuỗi
 * lệch nhau (ví dụ đã đăng ký ở app nhưng chưa register_did on-chain).
 */
export async function getLiveStatus(address: string) {
  const entity = await requireByAddress(address);
  const [didOnChain, admin, issuer, delegate] = await Promise.all([
    hasActiveDid(address),
    isActiveAdmin(address),
    isActiveIssuer(address),
    canDelegate(address),
  ]);
  return {
    entity,
    onChain: {
      hasActiveDid: didOnChain,
      isActiveAdmin: admin,
      isActiveIssuer: issuer,
      /** Được phép cấp quyền cho issuer khác (root, admin, hoặc issuer có bit uỷ quyền — F-02). */
      canDelegate: delegate,
    },
    /** true khi vai trò khai trong app khớp với quyền thật trên chuỗi. */
    consistent:
      entity.role === "issuer" ? issuer : entity.role === "admin" ? admin : didOnChain,
  };
}
