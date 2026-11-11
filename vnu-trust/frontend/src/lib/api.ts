/** Lớp gọi API. Token phiên giữ trong bộ nhớ + sessionStorage (không dùng localStorage
 *  để token không sống sót qua việc đóng tab). */
import { getBackend } from "./backend";

/** Đọc lại mỗi lần gọi để bộ chọn backend có hiệu lực ngay. */
const base = () => getBackend().base;
const TOKEN_KEY = "vnu_trust_session";

export const session = {
  get: (): string | null => {
    try {
      return sessionStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  },
  set: (t: string) => {
    try {
      sessionStorage.setItem(TOKEN_KEY, t);
    } catch { /* chế độ riêng tư có thể chặn */ }
  },
  clear: () => {
    try {
      sessionStorage.removeItem(TOKEN_KEY);
    } catch { /* bỏ qua */ }
  },
};

export class ApiError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = "ApiError";
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const token = session.get();
  const res = await fetch(base() + path, {
    method,
    headers: {
      ...(body ? { "content-type": "application/json" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await res.text();
  let payload: { success?: boolean; data?: T; error?: string } | string;
  try {
    payload = JSON.parse(text) as { success?: boolean; data?: T; error?: string };
  } catch {
    payload = text;
  }

  if (!res.ok) {
    if (res.status === 401) session.clear();
    const msg = typeof payload === "object" && payload.error ? payload.error : `Lỗi ${res.status}`;
    throw new ApiError(res.status, msg);
  }
  return (typeof payload === "object" ? (payload.data as T) : (payload as unknown as T));
}

export const api = {
  get: <T>(p: string) => request<T>("GET", p),
  post: <T>(p: string, b?: unknown) => request<T>("POST", p, b),
  del: <T>(p: string) => request<T>("DELETE", p),
};

// ---------- Kiểu dữ liệu dùng chung ----------

export type Role = "root" | "admin" | "issuer" | "holder" | "verifier";
export type VcStatus = "active" | "suspended" | "expired" | "revoked";

export interface Entity {
  address: string;
  did: string;
  role: Role;
  label: string;
  public_key_hex: string;
  created_at: string;
}

export interface Credential {
  vc_id: string;
  on_chain_vc_id: number | null;
  issuer_did: string;
  issuer_address: string;
  holder_did: string;
  holder_address: string;
  vc_type: number;
  ipfs_cid: string;
  content_hash: string;
  vc_json: Record<string, unknown>;
  status: VcStatus;
  status_reason: string | null;
  issued_at: string;
  expires_at: string | null;
  tx_hash: string;
  effective?: { status: VcStatus; source: "chain" | "db-index" | "db"; drift: boolean };
}

export interface Presentation {
  vp_id: string;
  holder_did: string;
  verifier_did: string | null;
  vc_ids: string[];
  ipfs_cid: string;
  created_at: string;
}

export interface ShareToken {
  token: string;
  vp_id: string;
  ipfs_cid: string;
  expires_at: string;
  revoked_at: string | null;
  view_count: number;
}

export interface ChainStats {
  admins: number;
  issuers: number;
  dids: number;
  credentials: number;
  chainId: number;
  ledgerVersion: string;
  rootAdmin: string;
  contract: string;
}

export interface ResolvedDid {
  did: string;
  source: "chain" | "db-index" | "cache";
  status: string;
  documentCid: string;
  documentHash: string;
  version: number;
  document: unknown;
  integrityOk: boolean | null;
}

export interface VerificationReport {
  vpId: string;
  holderDid: string;
  overallValid: boolean;
  checks: Array<{ name: string; passed: boolean; detail: string }>;
  credentials: Array<{ vcId: string; status: string; issuerDid: string; typeLabel: string }>;
  verifiedAt: string;
}
