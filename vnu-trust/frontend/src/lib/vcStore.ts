/**
 * Nối lớp mã hoá (vcCrypto.ts) với API — P3, 13/11/2026.
 *
 * Máy chủ chỉ giữ siêu dữ liệu (loại, ngày, trạng thái, CID, hash); nội dung văn bằng
 * nằm trong phong bì mã hoá tại `ipfs_cid`. Trình duyệt tải phong bì qua gateway công
 * khai `/ipfs/:cid`, giải mã bằng khoá riêng đang mở trong ví, rồi TỰ KIỂM với hash neo
 * trên chuỗi — thay cho phép kiểm máy chủ không còn làm được.
 */
import { api, type Credential } from "./api";
import { sha3_256Hex } from "./wallet";
import {
  encryptCredential, decryptCredential, checkCredential, encryptShare, decryptShare,
  type VcEnvelope, type ShareBlob,
} from "./vcCrypto";

interface WalletLike { address: string; publicKeyHex: string; keyPair: { privateKey: Uint8Array } }

const envelopes = new Map<string, Promise<VcEnvelope>>();
/** Phong bì là bất biến theo CID nên đệm được suốt phiên. */
export function loadEnvelope(cid: string): Promise<VcEnvelope> {
  let p = envelopes.get(cid);
  if (!p) {
    p = api.get<VcEnvelope>(`/ipfs/${encodeURIComponent(cid)}`);
    p.catch(() => envelopes.delete(cid));
    envelopes.set(cid, p);
  }
  return p;
}

export interface OpenedCredential { plain: Record<string, unknown>; problems: string[] }

/** Giải mã một văn bằng của chính mình (holder hoặc issuer đã cấp) và tự kiểm nó. */
export async function openCredential(c: Credential, wallet: WalletLike): Promise<OpenedCredential> {
  const env = await loadEnvelope(c.ipfs_cid);
  const plain = await decryptCredential(env, { address: wallet.address, privateKey: wallet.keyPair.privateKey });
  const problems = checkCredential(plain, {
    vcId: c.vc_id, contentHash: c.content_hash, holderDid: c.holder_did, vcIdHash: sha3_256Hex(c.vc_id),
  }, env);
  return { plain, problems };
}

/**
 * Issuer niêm phong nội dung cho holder và chính mình rồi ghim phong bì lên IPFS.
 * Khoá công khai của holder lấy từ danh bạ công khai — không cần holder trực tuyến.
 */
export async function sealCredential(
  vc: Record<string, unknown>, vcIdHash: string, holderAddress: string, wallet: WalletLike,
): Promise<string> {
  const holder = await api.get<{ public_key_hex: string }>(`/entities/by-address/${holderAddress}`);
  const env = await encryptCredential(vc, vcIdHash, [
    { address: holderAddress, role: "holder", ed25519PubHex: holder.public_key_hex },
    { address: wallet.address, role: "issuer", ed25519PubHex: wallet.publicKeyHex },
  ]);
  const { cid } = await api.post<{ cid: string }>("/ipfs/pin", { json: env, name: `vc-${vcIdHash.slice(-12)}` });
  return cid;
}

/** Mã hoá bản trình bày, ghim bản mã; trả CID và khoá để đặt vào `#k=` của liên kết. */
export async function sealPresentation(vp: Record<string, unknown>): Promise<{ cid: string; key: string }> {
  const { blob, key } = await encryptShare(vp);
  const { cid } = await api.post<{ cid: string }>("/ipfs/pin", { json: blob, name: `vp-${Date.now()}` });
  return { cid, key };
}

export async function openPresentation(cid: string, key: string): Promise<Record<string, unknown>> {
  const blob = await api.get<ShareBlob>(`/ipfs/${encodeURIComponent(cid)}`);
  return decryptShare(blob, key);
}

/** Tách mã chia sẻ và khoá từ một liên kết dán vào (…/verify/<token>#k=<key>) hoặc mã trơn. */
export function parseShareInput(input: string): { token: string; key: string | null } {
  const s = input.trim();
  const m = s.match(/verify\/([^#?/\s]+)(?:[^#]*)?(?:#k=([A-Za-z0-9_-]+))?/);
  if (m) return { token: decodeURIComponent(m[1]!), key: m[2] ?? null };
  const [token, frag] = s.split("#k=");
  return { token: token ?? "", key: frag || null };
}
