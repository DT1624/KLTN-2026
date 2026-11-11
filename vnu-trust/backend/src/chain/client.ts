import { cfg } from "../config/index.js";
import { upstream, badRequest } from "../utils/errors.js";
import { logger } from "../utils/logger.js";

const FULLNODE = cfg.CHAIN_FULLNODE.replace(/\/+$/, "");

async function rpc<T>(path: string, init?: RequestInit, timeoutMs = 15_000): Promise<T> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(`${FULLNODE}${path}`, { ...init, signal: ctrl.signal });
    const text = await res.text();
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
    if (!res.ok) throw upstream(`Fullnode trả ${res.status}`, body);
    return body as T;
  } catch (e) {
    if (e instanceof Error && e.name === "AbortError") {
      throw upstream(`Fullnode không phản hồi sau ${timeoutMs}ms`);
    }
    throw e;
  } finally {
    clearTimeout(timer);
  }
}

/** Gọi một hàm #[view] của contract. */
export async function view<T = unknown[]>(
  fn: string,
  args: unknown[] = [],
  typeArgs: string[] = [],
): Promise<T> {
  return rpc<T>("/view", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ function: fn, type_arguments: typeArgs, arguments: args }),
  });
}

/**
 * Gọi view nhưng nuốt lỗi abort của contract và trả về giá trị mặc định.
 * Nhiều view của contract abort khi không tìm thấy (ví dụ resolve_did),
 * trong khi tầng nghiệp vụ chỉ cần biết "không có".
 */
export async function viewOrNull<T>(fn: string, args: unknown[] = []): Promise<T | null> {
  try {
    return await view<T>(fn, args);
  } catch (e) {
    logger.debug({ fn, err: e }, "view trả lỗi, coi như không có dữ liệu");
    return null;
  }
}

export interface OnChainTx {
  hash: string;
  success: boolean;
  vm_status: string;
  sender: string;
  version: string;
  timestamp: string;
  payload?: { function?: string; arguments?: unknown[]; type?: string };
}

/** Lấy giao dịch theo hash. Trả null nếu fullnode chưa thấy giao dịch. */
export async function getTransaction(hash: string): Promise<OnChainTx | null> {
  if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) {
    throw badRequest("txHash không đúng định dạng (cần 0x + 64 ký tự hex)");
  }
  try {
    return await rpc<OnChainTx>(`/transactions/by_hash/${hash}`);
  } catch {
    return null;
  }
}

export interface VerifyTxOptions {
  /** Hàm entry mà giao dịch bắt buộc phải gọi. */
  expectedFunction: string;
  /** Địa chỉ bắt buộc phải là người gửi giao dịch. */
  expectedSender: string;
}

/**
 * Xác minh một giao dịch có thật, thành công, đúng hàm và đúng người gửi.
 *
 * Đây là điểm khác biệt quan trọng so với backend cũ: trước đây client gửi
 * lên `txHash` nào thì backend ghi thẳng vào CSDL, nên client hoàn toàn có
 * thể bịa ra một chuỗi hex và tạo bản ghi DID/VC giả mà không hề có giao
 * dịch nào trên chuỗi.
 */
export async function verifyTransaction(hash: string, opts: VerifyTxOptions): Promise<OnChainTx> {
  if (!cfg.VERIFY_ONCHAIN) {
    logger.warn({ hash }, "VERIFY_ONCHAIN=false — BỎ QUA xác minh giao dịch");
    return {
      hash,
      success: true,
      vm_status: "skipped",
      sender: opts.expectedSender,
      version: "0",
      timestamp: "0",
    };
  }

  const tx = await getTransaction(hash);
  if (!tx) throw badRequest("Không tìm thấy giao dịch này trên chuỗi");
  if (!tx.success) throw badRequest(`Giao dịch thất bại trên chuỗi: ${tx.vm_status}`);

  const fn = tx.payload?.function;
  if (fn !== opts.expectedFunction) {
    throw badRequest(`Giao dịch gọi hàm "${fn ?? "?"}", cần "${opts.expectedFunction}"`);
  }

  if (normalizeAddress(tx.sender) !== normalizeAddress(opts.expectedSender)) {
    throw badRequest("Người gửi giao dịch không khớp với tài khoản đang đăng nhập");
  }

  return tx;
}

/**
 * Chuẩn hoá địa chỉ Aptos/Movement về dạng 0x + 64 hex chữ thường.
 * Fullnode có thể trả về dạng đã rút gọn số 0 ở đầu (0x1), còn client
 * thường gửi dạng đầy đủ — so sánh chuỗi trực tiếp sẽ sai.
 */
export function normalizeAddress(addr: string): string {
  const hex = addr.trim().toLowerCase().replace(/^0x/, "");
  if (!/^[0-9a-f]{1,64}$/.test(hex)) throw badRequest(`Địa chỉ không hợp lệ: ${addr}`);
  return "0x" + hex.padStart(64, "0");
}

export async function chainHealth(): Promise<{ chainId: number; ledgerVersion: string | null }> {
  // Chế độ VERIFY_ONCHAIN=false không gọi fullnode: không có chuỗi thì không
  // có ledger version, và không nên tốn một vòng mạng cho mỗi lần xem trang chủ.
  if (!cfg.VERIFY_ONCHAIN) return { chainId: cfg.CHAIN_ID, ledgerVersion: null };
  const info = await rpc<{ chain_id: number; ledger_version: string }>("/");
  if (info.chain_id !== cfg.CHAIN_ID) {
    logger.warn(
      { expected: cfg.CHAIN_ID, actual: info.chain_id },
      "CHAIN_ID trong cấu hình không khớp fullnode — giao dịch sẽ bị từ chối BAD_CHAIN_ID",
    );
  }
  return { chainId: info.chain_id, ledgerVersion: info.ledger_version };
}
