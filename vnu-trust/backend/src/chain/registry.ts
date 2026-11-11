import { view, viewOrNull, normalizeAddress } from "./client.js";
import { VIEW, DID_STATUS, VC_STATUS, ROLE_STATUS, NO_PENDING_ROOT } from "./abi.js";
import * as offline from "./offline.js";

/**
 * Fullnode nhận tham số `vector<u8>` dưới dạng CHUỖI HEX, không phải mảng số.
 * Truyền mảng sẽ bị từ chối với "expect string<hex>".
 */
export function utf8ToHex(s: string): string {
  return "0x" + Buffer.from(s, "utf8").toString("hex");
}

/** Bytes on-chain (vector<u8>) trả về dạng "0x..." — đổi về chuỗi UTF-8. */
function hexToUtf8(hex: string): string {
  const clean = hex.replace(/^0x/, "");
  if (clean.length === 0) return "";
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return new TextDecoder().decode(bytes);
}

export interface OnChainDid {
  did: string;
  documentCid: string;
  documentHash: string;
  status: "active" | "suspended" | "revoked";
  version: number;
}

/** resolve_did trả về (did_string, document_cid, document_hash, status, version). */
function toDid(raw: unknown[]): OnChainDid | null {
  if (!Array.isArray(raw) || raw.length < 5) return null;
  const [didHex, cidHex, hashHex, status, version] = raw as [string, string, string, number, string];
  return {
    did: hexToUtf8(didHex),
    documentCid: hexToUtf8(cidHex),
    documentHash: String(hashHex),
    status: DID_STATUS[Number(status)] ?? "revoked",
    version: Number(version),
  };
}

export async function resolveDidOnChain(did: string): Promise<OnChainDid | null> {
  if (offline.OFFLINE) return offline.resolveDidOffline(did);
  const raw = await viewOrNull<unknown[]>(VIEW.resolveDid, [utf8ToHex(did)]);
  return raw ? toDid(raw) : null;
}

export async function resolveDidByOwner(address: string): Promise<OnChainDid | null> {
  if (offline.OFFLINE) return offline.resolveDidByOwnerOffline(address);
  const raw = await viewOrNull<unknown[]>(VIEW.resolveDidByOwner, [normalizeAddress(address)]);
  return raw ? toDid(raw) : null;
}

export async function hasActiveDid(address: string): Promise<boolean> {
  if (offline.OFFLINE) return offline.hasDidOffline(address);
  const r = await viewOrNull<[boolean]>(VIEW.hasActiveDid, [normalizeAddress(address)]);
  return r?.[0] === true;
}

export async function isActiveAdmin(address: string): Promise<boolean> {
  if (offline.OFFLINE) return offline.isAdminOffline(address);
  const r = await viewOrNull<[boolean]>(VIEW.isActiveAdmin, [normalizeAddress(address)]);
  return r?.[0] === true;
}

export async function isActiveIssuer(address: string): Promise<boolean> {
  if (offline.OFFLINE) return offline.isIssuerOffline(address);
  const r = await viewOrNull<[boolean]>(VIEW.isActiveIssuer, [normalizeAddress(address)]);
  return r?.[0] === true;
}

export async function getRootAdmin(): Promise<string | null> {
  if (offline.OFFLINE) return offline.rootFromDb();
  const r = await viewOrNull<[string]>(VIEW.getRootAdmin, []);
  return r?.[0] ?? null;
}

export async function getVcStatusOnChain(onChainVcId: number) {
  if (offline.OFFLINE) return offline.vcStatusOffline(onChainVcId);
  const r = await viewOrNull<[number]>(VIEW.getVcStatus, [String(onChainVcId)]);
  return r ? (VC_STATUS[Number(r[0])] ?? null) : null;
}

/** Đối chiếu hash nội dung VC lưu trên chuỗi với hash tính lại từ nội dung thật. */
export async function verifyVcIntegrity(onChainVcId: number, claimedHash: string): Promise<boolean> {
  if (offline.OFFLINE) return offline.vcIntegrityOffline(onChainVcId, claimedHash);
  const r = await viewOrNull<[boolean]>(VIEW.verifyIntegrity, [
    String(onChainVcId),
    claimedHash.startsWith("0x") ? claimedHash : "0x" + claimedHash,
  ]);
  return r?.[0] === true;
}

export async function authorityStats(): Promise<{ admins: number; issuers: number }> {
  if (offline.OFFLINE) {
    const c = await offline.countsOffline();
    return { admins: c.admins, issuers: c.issuers };
  }
  const r = await view<[string, string]>(VIEW.authorityStats, []);
  return { admins: Number(r[0]), issuers: Number(r[1]) };
}

export async function totalDids(): Promise<number> {
  if (offline.OFFLINE) return (await offline.countsOffline()).dids;
  const r = await view<[string]>(VIEW.totalDids, []);
  return Number(r[0]);
}

export async function totalVcs(): Promise<number> {
  if (offline.OFFLINE) return (await offline.countsOffline()).vcs;
  const r = await view<[string]>(VIEW.totalVcs, []);
  return Number(r[0]);
}

/** Địa chỉ này có được phép cấp quyền cho issuer khác không (F-02)? */
export async function canDelegate(address: string): Promise<boolean> {
  if (offline.OFFLINE) return offline.canDelegateOffline(address);
  const r = await viewOrNull<[boolean]>(VIEW.canDelegate, [normalizeAddress(address)]);
  return r?.[0] === true;
}

/**
 * Địa chỉ đang được đề cử làm root nhưng chưa ký nhận.
 * Trả null khi không có đề cử nào — contract dùng @0x0 cho trạng thái đó.
 */
export async function getPendingRoot(): Promise<string | null> {
  if (offline.OFFLINE) return null;
  const r = await viewOrNull<[string]>(VIEW.getPendingRoot, []);
  if (!r?.[0]) return null;
  const addr = normalizeAddress(r[0]);
  return addr === NO_PENDING_ROOT ? null : addr;
}

export interface OnChainRole {
  approvedBy: string;
  vcTypeMask: number;
  delegationVcCid: string;
  delegationVcHash: string;
  expiresAt: number;
  status: string;
}

/**
 * Bản ghi vai trò on-chain của một địa chỉ.
 * `get_info` abort khi địa chỉ chưa từng được cấp vai trò nào — ở đây coi đó
 * là "không có vai trò" thay vì lỗi, vì tầng nghiệp vụ chỉ cần biết có hay không.
 */
export async function getRoleInfo(address: string): Promise<OnChainRole | null> {
  if (offline.OFFLINE) return offline.roleInfoOffline(address);
  const raw = await viewOrNull<unknown[]>(VIEW.getInfo, [normalizeAddress(address)]);
  if (!Array.isArray(raw) || raw.length < 6) return null;
  const [approvedBy, mask, cidHex, hashHex, expiresAt, status] = raw as
    [string, string, string, string, string, number];
  return {
    approvedBy: String(approvedBy),
    vcTypeMask: Number(mask),
    delegationVcCid: hexToUtf8(String(cidHex)),
    delegationVcHash: String(hashHex),
    expiresAt: Number(expiresAt),
    status: ROLE_STATUS[Number(status)] ?? "unknown",
  };
}

/** Số VC đang còn hiệu lực (đã trừ phần bị thu hồi) — F-11e. */
export async function liveCounts(
  issuer: string,
  holder: string,
): Promise<{ issued: number; held: number }> {
  if (offline.OFFLINE) return offline.liveCountsOffline(issuer, holder);
  const r = await viewOrNull<[string, string]>(VIEW.getLiveCounts, [
    normalizeAddress(issuer),
    normalizeAddress(holder),
  ]);
  return { issued: Number(r?.[0] ?? 0), held: Number(r?.[1] ?? 0) };
}
