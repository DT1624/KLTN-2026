import { badRequest } from "../utils/errors.js";
import { fetchJSON } from "./ipfs.service.js";
import { normalizeAddress } from "../chain/client.js";

/**
 * Kiểm CẤU TRÚC phong bì văn bằng và bản trình bày đã mã hoá (P3, 13/11/2026).
 *
 * Máy chủ không còn thấy bản rõ nên KHÔNG kiểm được `contentHash` lúc cấp nữa. Rào
 * thay thế: (1) ví holder tự kiểm hash + DID sau khi giải mã (frontend/src/lib/vcCrypto.ts
 * checkCredential); (2) bước xác minh 7 đối chiếu bản rõ người xác minh nhận được với
 * hash neo trên chuỗi; (3) ở đây — phong bì đúng định dạng, gắn với đúng văn bằng
 * (aad), có ĐÚNG holder và issuer là người nhận, và KHÔNG mang trường lạ nào (chặn
 * việc nhét bản rõ vào cạnh bản mã).
 *
 * Phải giống hệt backend Go (internal/services/envelope.go): cùng thứ tự, cùng thông điệp.
 */

const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
const MAX_CT = 64 * 1024;
const MAX_SHARE_CT = 1024 * 1024;

function b64len(v: unknown, field: string): number {
  if (typeof v !== "string" || !B64.test(v) || v.length % 4 !== 0) {
    throw badRequest(`Phong bì không hợp lệ: ${field} phải là base64`);
  }
  return Buffer.from(v, "base64").length;
}

function exactKeys(o: unknown, keys: string[], what: string): Record<string, unknown> {
  if (!o || typeof o !== "object" || Array.isArray(o)) throw badRequest(`Phong bì không hợp lệ: ${what} phải là đối tượng`);
  const got = Object.keys(o).sort().join(",");
  if (got !== [...keys].sort().join(",")) {
    throw badRequest(`Phong bì không hợp lệ: ${what} chỉ được có các trường ${keys.join(", ")}`);
  }
  return o as Record<string, unknown>;
}

async function load(cid: string, what: string): Promise<unknown> {
  try {
    return await fetchJSON(cid);
  } catch {
    throw badRequest(`Không đọc được ${what} tại CID ${cid}`);
  }
}

/** Phong bì văn bằng tại `cid`: gắn với `vcIdHash`, người nhận đúng là holder + issuer. */
export async function assertEnvelope(cid: string, vcIdHash: string, holder: string, issuer: string): Promise<void> {
  const env = exactKeys(await load(cid, "phong bì văn bằng"), ["v", "alg", "aad", "iv", "ct", "recipients"], "phong bì");
  if (env.v !== 1 || env.alg !== "A256GCM") throw badRequest("Phong bì không hợp lệ: chỉ hỗ trợ v=1, alg=A256GCM");
  if (env.aad !== `vnu-vc:${vcIdHash.toLowerCase()}`) throw badRequest("Phong bì không hợp lệ: aad không gắn với văn bằng này");
  if (b64len(env.iv, "iv") !== 12) throw badRequest("Phong bì không hợp lệ: iv phải 12 byte");
  const ct = b64len(env.ct, "ct");
  if (ct < 16 || ct > MAX_CT) throw badRequest("Phong bì không hợp lệ: kích thước bản mã ngoài khoảng cho phép");
  const recipients = env.recipients;
  if (!Array.isArray(recipients) || recipients.length < 2 || recipients.length > 4) {
    throw badRequest("Phong bì không hợp lệ: cần 2..4 người nhận");
  }
  const kids = new Set<string>();
  let holders = 0;
  let issuers = 0;
  for (const raw of recipients) {
    const r = exactKeys(raw, ["kid", "role", "epk", "iv", "wk"], "người nhận");
    let kid: string;
    try {
      kid = normalizeAddress(String(r.kid));
    } catch {
      throw badRequest("Phong bì không hợp lệ: kid phải là địa chỉ");
    }
    if (kids.has(kid)) throw badRequest("Phong bì không hợp lệ: người nhận trùng lặp");
    kids.add(kid);
    if (r.role !== "holder" && r.role !== "issuer") throw badRequest("Phong bì không hợp lệ: role phải là holder hoặc issuer");
    if (b64len(r.epk, "epk") !== 32 || b64len(r.iv, "iv") !== 12 || b64len(r.wk, "wk") !== 48) {
      throw badRequest("Phong bì không hợp lệ: khoá bọc sai kích thước");
    }
    if (r.role === "holder" && kid === normalizeAddress(holder)) holders++;
    if (r.role === "issuer" && kid === normalizeAddress(issuer)) issuers++;
  }
  if (holders !== 1) throw badRequest("Phong bì không hợp lệ: holder không nằm trong danh sách người nhận");
  if (issuers !== 1) throw badRequest("Phong bì không hợp lệ: issuer không nằm trong danh sách người nhận");
}

/** Bản trình bày đã mã hoá tại `cid` (khoá nằm trong fragment liên kết, không ở máy chủ). */
export async function assertShareBlob(cid: string): Promise<void> {
  const blob = exactKeys(await load(cid, "bản trình bày đã mã hoá"), ["v", "alg", "iv", "ct"], "bản trình bày");
  if (blob.v !== 1 || blob.alg !== "A256GCM") throw badRequest("Phong bì không hợp lệ: chỉ hỗ trợ v=1, alg=A256GCM");
  if (b64len(blob.iv, "iv") !== 12) throw badRequest("Phong bì không hợp lệ: iv phải 12 byte");
  const ct = b64len(blob.ct, "ct");
  if (ct < 16 || ct > MAX_SHARE_CT) throw badRequest("Phong bì không hợp lệ: kích thước bản mã ngoài khoảng cho phép");
}

/**
 * Tuyến công khai GET /ipfs/:cid chỉ phục vụ thứ công khai THEO THIẾT KẾ: DID Document,
 * phong bì văn bằng và bản trình bày đã mã hoá. JSON khác (vd. một client cẩu thả ghim
 * văn bằng dạng rõ) không được phát lại công khai qua máy chủ. Giống envelope.go.
 */
export function isPublicPinned(v: unknown): boolean {
  if (!v || typeof v !== "object" || Array.isArray(v)) return false;
  const keys = Object.keys(v).sort().join(",");
  if (keys === "aad,alg,ct,iv,recipients,v" || keys === "alg,ct,iv,v") return true;
  const o = v as Record<string, unknown>;
  return typeof o.id === "string" && o.id.startsWith("did:") && "@context" in o;
}
