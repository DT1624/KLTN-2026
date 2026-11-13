/**
 * Mã hoá nội dung văn bằng trên thiết bị (P3, 13/11/2026).
 *
 * Trước đây nội dung văn bằng nằm DẠNG RÕ trên IPFS và trong CSDL máy chủ: ai có
 * CID là đọc được họ tên, mã sinh viên, điểm. Nay:
 *
 *   nội dung ──AES-256-GCM(CEK ngẫu nhiên, aad = "vnu-vc:<vcIdHash>")──▶ ct
 *   CEK ──ECIES cho TỪNG người nhận──▶ recipients[] = { kid, role, epk, iv, wk }
 *        X25519(khoá tạm, khoá X25519 của người nhận)   ← dẫn từ khoá Ed25519 của ví
 *        → HKDF-SHA256(salt = epk ‖ pub người nhận, info = WRAP_INFO + kid)
 *        → AES-256-GCM bọc CEK (aad = aad văn bằng + "|" + kid)
 *
 * Người nhận: holder và issuer (issuer cần để cấp lại / đối soát). KHÔNG có khoá lưu
 * giữ của nhà trường (người dùng chọn 13/11). Khoá công khai Ed25519 của mọi người đã
 * nằm trong danh bạ công khai, nên issuer mã hoá cho holder mà không cần holder trực
 * tuyến. Dùng chung khoá Ed25519 cho ký và trao đổi khoá là cách libsodium làm
 * (crypto_sign_ed25519_sk_to_curve25519) — giới hạn đã ghi trong báo cáo.
 *
 * `content_hash` trên chuỗi vẫn là SHA3-256 của bản RÕ chuẩn hoá (bất biến #5, bước
 * xác minh 7 giữ nguyên). Bản rõ chứa `id = urn:uuid` ngẫu nhiên 122 bit nên hash
 * không dò ngược được.
 *
 * Chia sẻ cho người xác minh: holder giải mã, dựng VP, mã hoá VP bằng khoá ngẫu nhiên
 * K đặt trong FRAGMENT của liên kết (`#k=…`) — trình duyệt không gửi fragment lên
 * máy chủ, nên máy chủ và IPFS chỉ giữ bản mã.
 */
import { x25519, edwardsToMontgomeryPub, edwardsToMontgomeryPriv } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import { canonicalize, sha3_256Hex } from "./wallet";

export const VC_ALG = "A256GCM" as const;
const WRAP_INFO = "vnu-trust/vc-key-wrap/v1";

export interface Recipient { kid: string; role: "holder" | "issuer"; epk: string; iv: string; wk: string }
/** Phong bì văn bằng — thứ DUY NHẤT được ghim lên IPFS. Hai backend kiểm đúng các trường này. */
export interface VcEnvelope { v: 1; alg: typeof VC_ALG; aad: string; iv: string; ct: string; recipients: Recipient[] }
/** Bản trình bày đã mã hoá bằng khoá trong fragment liên kết. */
export interface ShareBlob { v: 1; alg: typeof VC_ALG; iv: string; ct: string }

const enc = new TextEncoder();
const dec = new TextDecoder();

// base64 theo khối — dùng spread cho cả mảng lớn sẽ tràn ngăn xếp.
function b64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export const toB64url = (b: Uint8Array) => b64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
export const fromB64url = (s: string) => unb64(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));

const concat = (a: Uint8Array, b: Uint8Array) => { const o = new Uint8Array(a.length + b.length); o.set(a); o.set(b, a.length); return o; };
const normAddr = (a: string) => "0x" + a.replace(/^0x/i, "").toLowerCase().padStart(64, "0");
const hexToBytes = (h: string) => Uint8Array.from((h.replace(/^0x/i, "").match(/../g) ?? []).map((x) => parseInt(x, 16)));

// TS 5.7+ coi Uint8Array<ArrayBufferLike> không phải BufferSource; mọi mảng ở đây đều
// nằm trên ArrayBuffer thường nên ép kiểu là an toàn.
const bs = (u: Uint8Array) => u as unknown as BufferSource;

async function gcm(mode: "encrypt" | "decrypt", key: Uint8Array, iv: Uint8Array, data: Uint8Array, aad: string): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", bs(key), { name: "AES-GCM" }, false, [mode]);
  const params = { name: "AES-GCM", iv: bs(iv), additionalData: bs(enc.encode(aad)) };
  const out = mode === "encrypt"
    ? await crypto.subtle.encrypt(params, k, bs(data))
    : await crypto.subtle.decrypt(params, k, bs(data));
  return new Uint8Array(out);
}

function kek(shared: Uint8Array, epk: Uint8Array, recipientPub: Uint8Array, kid: string): Uint8Array {
  return hkdf(sha256, shared, concat(epk, recipientPub), `${WRAP_INFO}:${normAddr(kid)}`, 32);
}

/** Khoá X25519 công khai của một địa chỉ, từ khoá công khai Ed25519 trong danh bạ. */
export const x25519PubFromEd25519 = (ed25519PubHex: string) => edwardsToMontgomeryPub(hexToBytes(ed25519PubHex));

export const envelopeAad = (vcIdHash: string) => `vnu-vc:${vcIdHash.toLowerCase()}`;

/** Issuer mã hoá nội dung văn bằng cho holder và chính mình. */
export async function encryptCredential(
  plain: Record<string, unknown>,
  vcIdHash: string,
  to: { address: string; role: Recipient["role"]; ed25519PubHex: string }[],
): Promise<VcEnvelope> {
  const cek = randomBytes(32);
  const iv = randomBytes(12);
  const aad = envelopeAad(vcIdHash);
  const ct = await gcm("encrypt", cek, iv, enc.encode(canonicalize(plain)), aad);
  const recipients: Recipient[] = [];
  for (const r of to) {
    const kid = normAddr(r.address);
    const rpub = x25519PubFromEd25519(r.ed25519PubHex);
    const eph = x25519.utils.randomPrivateKey();
    const epk = x25519.getPublicKey(eph);
    const wiv = randomBytes(12);
    const wk = await gcm("encrypt", kek(x25519.getSharedSecret(eph, rpub), epk, rpub, kid), wiv, cek, `${aad}|${kid}`);
    recipients.push({ kid, role: r.role, epk: b64(epk), iv: b64(wiv), wk: b64(wk) });
  }
  return { v: 1, alg: VC_ALG, aad, iv: b64(iv), ct: b64(ct), recipients };
}

/**
 * Người nhận giải mã bằng khoá riêng Ed25519 đang mở trong ví. Ném lỗi khi ví
 * không phải người nhận, hoặc khi bản mã / khoá bọc / aad bị sửa (GCM phát hiện).
 */
export async function decryptCredential(
  env: VcEnvelope,
  wallet: { address: string; privateKey: Uint8Array },
): Promise<Record<string, unknown>> {
  const kid = normAddr(wallet.address);
  const r = env.recipients.find((x) => normAddr(x.kid) === kid);
  if (!r) throw new Error("Ví này không nằm trong danh sách người được đọc văn bằng");
  const xpriv = edwardsToMontgomeryPriv(wallet.privateKey);
  const epk = unb64(r.epk);
  const shared = x25519.getSharedSecret(xpriv, epk);
  const cek = await gcm("decrypt", kek(shared, epk, x25519.getPublicKey(xpriv), kid), unb64(r.iv), unb64(r.wk), `${env.aad}|${kid}`);
  const plain = await gcm("decrypt", cek, unb64(env.iv), unb64(env.ct), env.aad);
  return JSON.parse(dec.decode(plain)) as Record<string, unknown>;
}

/**
 * Kiểm bản rõ vừa giải mã với dữ liệu đã neo — thay cho phép kiểm `contentHash`
 * mà máy chủ không còn làm được (máy chủ không thấy bản rõ nữa).
 */
export function checkCredential(
  plain: Record<string, unknown>,
  expected: { vcId: string; contentHash: string; holderDid: string; vcIdHash?: string },
  env?: VcEnvelope,
): string[] {
  const problems: string[] = [];
  if (sha3_256Hex(plain) !== expected.contentHash.toLowerCase()) problems.push("Hash nội dung không khớp bản neo trên chuỗi");
  if (plain.id !== expected.vcId) problems.push("Mã văn bằng trong nội dung không khớp");
  const subj = plain.credentialSubject as Record<string, unknown> | undefined;
  if (subj?.id !== expected.holderDid) problems.push("Văn bằng không cấp cho DID của bạn");
  if (env && expected.vcIdHash && env.aad !== envelopeAad(expected.vcIdHash)) problems.push("Phong bì không gắn với văn bằng này");
  return problems;
}

/** Mã hoá bản trình bày bằng khoá ngẫu nhiên; khoá trả về để đặt vào `#k=` của liên kết. */
export async function encryptShare(vp: Record<string, unknown>): Promise<{ blob: ShareBlob; key: string }> {
  const k = randomBytes(32);
  const iv = randomBytes(12);
  const ct = await gcm("encrypt", k, iv, enc.encode(canonicalize(vp)), "vnu-vp");
  return { blob: { v: 1, alg: VC_ALG, iv: b64(iv), ct: b64(ct) }, key: toB64url(k) };
}

export async function decryptShare(blob: ShareBlob, key: string): Promise<Record<string, unknown>> {
  const plain = await gcm("decrypt", fromB64url(key), unb64(blob.iv), unb64(blob.ct), "vnu-vp");
  return JSON.parse(dec.decode(plain)) as Record<string, unknown>;
}
