import { cfg } from "../config/index.js";
import { queryOne } from "../db/pool.js";
import { normalizeAddress } from "./client.js";
import { logger } from "../utils/logger.js";

/**
 * Chế độ không phụ thuộc chuỗi (VERIFY_ONCHAIN=false).
 *
 * Chỉ dùng khi phát triển hoặc chạy kiểm thử tự động, lúc chưa có chuỗi thật
 * hoặc chuỗi bị dựng lại. Khi đó các câu hỏi "địa chỉ này có phải issuer đang
 * hoạt động không" được trả lời bằng **chỉ mục trong CSDL** thay vì view
 * function trên chuỗi.
 *
 * Cố ý KHÔNG trả `true` vô điều kiện: luồng phân quyền vẫn phải có ý nghĩa —
 * một holder vẫn bị chặn khỏi tuyến issuer — nếu không thì bài kiểm thử chẳng
 * chứng minh được điều gì.
 */
export const OFFLINE = !cfg.VERIFY_ONCHAIN;

let warned = false;
function warnOnce(): void {
  if (warned) return;
  warned = true;
  logger.warn(
    "VERIFY_ONCHAIN=false — quyền và trạng thái DID đọc từ CSDL thay vì chuỗi. " +
      "TUYỆT ĐỐI không bật cấu hình này ở môi trường thật.",
  );
}

/** Vai trò khai báo trong bảng entities. `root` được coi là admin. */
export async function roleFromDb(address: string): Promise<string | null> {
  warnOnce();
  const row = await queryOne<{ role: string }>(
    "SELECT role FROM entities WHERE address = $1",
    [normalizeAddress(address)],
  );
  return row?.role ?? null;
}

/** Root theo chỉ mục: hàng duy nhất có role='root' (accept_root giữ bất biến đó). */
export async function rootFromDb(): Promise<string | null> {
  warnOnce();
  const row = await queryOne<{ address: string }>(
    "SELECT address FROM entities WHERE role = 'root' ORDER BY updated_at DESC LIMIT 1",
  );
  return row?.address ?? null;
}

export async function isAdminOffline(address: string): Promise<boolean> {
  const r = await roleFromDb(address);
  return r === "admin" || r === "root";
}

export async function isIssuerOffline(address: string): Promise<boolean> {
  return (await roleFromDb(address)) === "issuer";
}

export async function hasDidOffline(address: string): Promise<boolean> {
  warnOnce();
  const row = await queryOne<{ n: string }>(
    `SELECT 1 AS n FROM did_documents d
       JOIN entities e ON e.id = d.entity_id
      WHERE e.address = $1 AND d.status = 'active'`,
    [normalizeAddress(address)],
  );
  return row !== null;
}

export interface OfflineDid {
  did: string;
  documentCid: string;
  documentHash: string;
  status: "active" | "suspended" | "revoked";
  version: number;
}

const DID_COLS = "did, document_cid, document_hash, status, version";

type DidRow = {
  did: string;
  document_cid: string;
  document_hash: string;
  status: string;
  version: number;
};

function toOfflineDid(r: DidRow): OfflineDid {
  return {
    did: r.did,
    documentCid: r.document_cid,
    documentHash: r.document_hash,
    status: r.status as OfflineDid["status"],
    version: Number(r.version),
  };
}

export async function resolveDidOffline(did: string): Promise<OfflineDid | null> {
  warnOnce();
  const r = await queryOne<DidRow>(
    `SELECT ${DID_COLS} FROM did_documents WHERE did = $1`,
    [did],
  );
  return r ? toOfflineDid(r) : null;
}

export async function resolveDidByOwnerOffline(address: string): Promise<OfflineDid | null> {
  warnOnce();
  const r = await queryOne<DidRow>(
    `SELECT ${DID_COLS.split(", ").map((c) => "d." + c).join(", ")}
       FROM did_documents d JOIN entities e ON e.id = d.entity_id
      WHERE e.address = $1`,
    [normalizeAddress(address)],
  );
  return r ? toOfflineDid(r) : null;
}

export type OfflineVcStatus = "active" | "suspended" | "expired" | "revoked";

export async function vcStatusOffline(onChainVcId: number): Promise<OfflineVcStatus | null> {
  warnOnce();
  const r = await queryOne<{ status: OfflineVcStatus }>(
    "SELECT status FROM credentials WHERE on_chain_vc_id = $1",
    [onChainVcId],
  );
  return r?.status ?? null;
}

export async function vcIntegrityOffline(onChainVcId: number, hash: string): Promise<boolean> {
  warnOnce();
  const r = await queryOne<{ content_hash: string }>(
    "SELECT content_hash FROM credentials WHERE on_chain_vc_id = $1",
    [onChainVcId],
  );
  if (!r) return false;
  const norm = (h: string) => (h.startsWith("0x") ? h : "0x" + h).toLowerCase();
  return norm(r.content_hash) === norm(hash);
}

export async function countsOffline(): Promise<{
  admins: number;
  issuers: number;
  dids: number;
  vcs: number;
}> {
  warnOnce();
  const r = await queryOne<{ admins: string; issuers: string; dids: string; vcs: string }>(
    `SELECT
       (SELECT count(*) FROM entities WHERE role IN ('admin','root')) AS admins,
       (SELECT count(*) FROM entities WHERE role = 'issuer')          AS issuers,
       (SELECT count(*) FROM did_documents)                            AS dids,
       (SELECT count(*) FROM credentials)                              AS vcs`,
  );
  return {
    admins: Number(r?.admins ?? 0),
    issuers: Number(r?.issuers ?? 0),
    dids: Number(r?.dids ?? 0),
    vcs: Number(r?.vcs ?? 0),
  };
}

/**
 * Ở chế độ không phụ thuộc chuỗi, "được phép uỷ quyền lại" quy về vai trò khai
 * báo: chỉ admin/root. Không suy ra bit VC_DELEGATION được vì bit đó chỉ tồn
 * tại trên chuỗi — và nói dối là có thì bài kiểm thử mất hết ý nghĩa.
 */
export async function canDelegateOffline(address: string): Promise<boolean> {
  return isAdminOffline(address);
}

export interface OfflineRole {
  approvedBy: string;
  vcTypeMask: number;
  delegationVcCid: string;
  delegationVcHash: string;
  expiresAt: number;
  status: string;
}

export async function roleInfoOffline(address: string): Promise<OfflineRole | null> {
  const role = await roleFromDb(address);
  if (role !== "admin" && role !== "root" && role !== "issuer") return null;
  return {
    approvedBy: "",
    vcTypeMask: 0,
    delegationVcCid: "",
    delegationVcHash: "",
    expiresAt: 0,
    status: "active",
  };
}

export async function liveCountsOffline(
  issuer: string,
  holder: string,
): Promise<{ issued: number; held: number }> {
  warnOnce();
  const r = await queryOne<{ issued: string; held: string }>(
    // Khớp bộ đếm "sống" của contract: chỉ VC đang ACTIVE. Tạm ngưng cũng
    // không tính — trước đây điều kiện `status <> 'revoked'` đếm cả VC tạm ngưng.
    `SELECT
       (SELECT count(*) FROM credentials
         WHERE issuer_address = $1 AND status = 'active') AS issued,
       (SELECT count(*) FROM credentials
         WHERE holder_address = $2 AND status = 'active') AS held`,
    [normalizeAddress(issuer), normalizeAddress(holder)],
  );
  return { issued: Number(r?.issued ?? 0), held: Number(r?.held ?? 0) };
}
