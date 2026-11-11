/**
 * TẦNG CHUỖI CỦA TRÌNH DUYỆT — ký và gửi giao dịch ngay tại đây.
 *
 * Trước đây mọi biểu mẫu đều có ô "Mã giao dịch": người dùng phải mở một ví
 * ngoài, tự gọi hàm, chép hash rồi dán lại vào giao diện. Vô lý, vì khoá riêng
 * đã nằm sẵn trong bộ nhớ tab này rồi — trình duyệt ký được thì nó phải tự ký.
 *
 * KHÔNG DÙNG APTOS SDK (giữ quyết định #4: gói SDK ~4,7MB cho vài phép ký).
 * Thay vào đó nhờ chính fullnode BCS hoá hộ:
 *
 *     POST /v1/transactions/encode_submission   { tx chưa ký }  -> hex cần ký
 *     ed25519.sign(hex, khoá riêng trong bộ nhớ)
 *     POST /v1/transactions                     { tx + signature } -> { hash }
 *     GET  /v1/transactions/by_hash/{hash}      cho tới khi hết "pending"
 *
 * Đánh đổi: thêm một vòng gọi mạng mỗi giao dịch. Đổi lại bundle nhỏ hơn 14 lần
 * và không kéo theo phụ thuộc nào mới.
 *
 * ĐÂY KHÔNG PHẢI VÍ TIỀN. Không có hàm chuyển token và sẽ không thêm. Thứ duy
 * nhất liên quan tới token là `faucet()` — xin token testnet để CÓ GAS mà gọi
 * hàm entry của hợp đồng.
 */
import { ed25519 } from "@noble/curves/ed25519";
import { canonicalize, sha3_256Hex, type UnlockedWallet } from "./wallet";

// ---------- Cấu hình ----------

const env = import.meta.env;

export const CHAIN = {
  fullnode: (env.VITE_CHAIN_FULLNODE ?? "https://testnet.movementnetwork.xyz/v1").replace(/\/$/, ""),
  faucet: (env.VITE_CHAIN_FAUCET ?? "https://faucet.testnet.movementnetwork.xyz").replace(/\/$/, ""),
  explorer: (env.VITE_CHAIN_EXPLORER ?? "https://explorer.movementnetwork.xyz/txn").replace(/\/$/, ""),
  chainId: Number(env.VITE_CHAIN_ID ?? 250),
  /** Địa chỉ gói Move. Một biến duy nhất cho cả hệ thống — xem `chain.env`. */
  contract: env.VITE_CONTRACT_ADDRESS ?? "",
} as const;

/** Có cấu hình đủ để nói chuyện với chuỗi hay không. */
export const chainConfigured = (): boolean =>
  /^0x[0-9a-fA-F]{1,64}$/.test(CHAIN.contract) && CHAIN.contract !== "0x0";

/** Đường xem giao dịch trên explorer — kèm mạng vì explorer phục vụ nhiều mạng. */
export const explorerTxUrl = (hash: string) => `${CHAIN.explorer}/${hash}?network=testnet`;

const MODULE = {
  didRegistry: `${CHAIN.contract}::did_registry`,
  authority: `${CHAIN.contract}::authority`,
  vcRegistry: `${CHAIN.contract}::vc_registry`,
} as const;

/**
 * Tên hàm entry. Phải khớp tuyệt đối với `backend/src/chain/abi.ts`,
 * `backend-go/internal/chain/abi.go` và mã Move — `scripts/abi-check.mjs`
 * đối chiếu cả ba nơi này với chính nguồn Move.
 */
export const ENTRY = {
  registerDid: `${MODULE.didRegistry}::register_did`,
  updateDidDocument: `${MODULE.didRegistry}::update_did_document`,
  suspendOwnDid: `${MODULE.didRegistry}::suspend_own_did`,
  reactivateOwnDid: `${MODULE.didRegistry}::reactivate_own_did`,

  grantAdmin: `${MODULE.authority}::grant_admin`,
  revokeAdmin: `${MODULE.authority}::revoke_admin`,
  approveIssuer: `${MODULE.authority}::approve_issuer`,
  suspendIssuer: `${MODULE.authority}::suspend_issuer`,
  reactivateIssuer: `${MODULE.authority}::reactivate_issuer`,
  revokeIssuer: `${MODULE.authority}::revoke_issuer`,

  proposeRoot: `${MODULE.authority}::propose_root`,
  acceptRoot: `${MODULE.authority}::accept_root`,
  cancelRootTransfer: `${MODULE.authority}::cancel_root_transfer`,

  adminSuspendDid: `${MODULE.authority}::admin_suspend_did`,
  adminReactivateDid: `${MODULE.authority}::admin_reactivate_did`,
  adminRevokeDid: `${MODULE.authority}::admin_revoke_did`,

  issueVc: `${MODULE.vcRegistry}::issue_vc`,
  suspendVc: `${MODULE.vcRegistry}::suspend_vc`,
  revokeVc: `${MODULE.vcRegistry}::revoke_vc`,
  // Cố ý KHÔNG khai `admin_suspend_vc`: backend xác minh giao dịch tạm ngưng
  // bằng tên `suspend_vc` nên gửi hàm kia thì chuỗi nhận mà backend từ chối ghi
  // chỉ mục. Tạm ngưng là việc của đơn vị cấp bằng; admin chỉ thu hồi và kích
  // hoạt lại. (`scripts/abi-check.mjs` bắt đúng chỗ lệch này.)
  adminReinstateVc: `${MODULE.vcRegistry}::admin_reinstate_vc`,
  adminRevokeVc: `${MODULE.vcRegistry}::admin_revoke_vc`,
} as const;

export const VIEW = {
  resolveDidByOwner: `${MODULE.didRegistry}::resolve_did_by_owner`,
  hasActiveDid: `${MODULE.didRegistry}::has_active_did`,
  isActiveAdmin: `${MODULE.authority}::is_active_admin`,
  isActiveIssuer: `${MODULE.authority}::is_active_issuer`,
  canDelegate: `${MODULE.authority}::can_delegate`,
  getRootAdmin: `${MODULE.authority}::get_root_admin`,
  getPendingRoot: `${MODULE.authority}::get_pending_root`,
  getInfo: `${MODULE.authority}::get_info`,
} as const;

// ---------- Mã hoá tham số ----------

const enc = new TextEncoder();
const toHex = (b: Uint8Array) =>
  "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");

/**
 * `vector<u8>` phải gửi lên fullnode dưới dạng CHUỖI HEX, không phải mảng số —
 * truyền mảng bị từ chối thẳng với `expect string<hex>` (quyết định #6).
 */
export const bytesArg = (s: string): string => toHex(enc.encode(s));

/** Hash/CID sẵn dạng `0x…` thì giữ nguyên; chuỗi thường thì mã hoá UTF-8. */
export const hashArg = (hex: string): string =>
  /^0x[0-9a-fA-F]*$/.test(hex) ? hex.toLowerCase() : bytesArg(hex);

/** u64 luôn gửi dạng chuỗi để không mất chính xác khi vượt 2^53. */
export const u64Arg = (n: number | bigint): string => String(n);

// ---------- Gọi fullnode ----------

class ChainError extends Error {
  constructor(message: string, public readonly detail?: unknown) {
    super(message);
    this.name = "ChainError";
  }
}

async function node<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(CHAIN.fullnode + path, init);
  } catch {
    throw new ChainError(`Không kết nối được fullnode ${CHAIN.fullnode}`);
  }
  const text = await res.text();
  let body: unknown;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  if (!res.ok) {
    const msg =
      typeof body === "object" && body && "message" in body
        ? String((body as { message: unknown }).message)
        : `Fullnode trả lỗi ${res.status}`;
    throw new ChainError(msg, body);
  }
  return body as T;
}

const jsonPost = (body: unknown): RequestInit => ({
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(body),
});

// ---------- Đọc trạng thái tài khoản ----------

export async function getSequenceNumber(address: string): Promise<string> {
  try {
    const info = await node<{ sequence_number: string }>(`/accounts/${address}`);
    return info.sequence_number;
  } catch {
    // Tài khoản chưa tồn tại trên chuỗi (chưa nhận đồng nào) — chuỗi coi
    // sequence là 0, nhưng giao dịch vẫn sẽ hỏng vì không có gas.
    return "0";
  }
}

/** Số dư tính bằng octas (1 MOVE = 100.000.000 octas). */
export async function getBalance(address: string): Promise<bigint> {
  try {
    const raw = await node<string | number>(
      `/accounts/${address}/balance/0x1::aptos_coin::AptosCoin`,
    );
    return BigInt(raw as string);
  } catch {
    return 0n;
  }
}

export const OCTAS = 100_000_000n;
export const formatMove = (octas: bigint): string =>
  (Number(octas) / Number(OCTAS)).toLocaleString("vi-VN", { maximumFractionDigits: 4 });

/**
 * Tự phục vụ gas.
 *
 * Mỗi tài khoản tự xin token testnet cho chính mình — KHÔNG có chuyện tài khoản
 * này gửi token cho tài khoản kia, hệ thống không có chức năng đó. Token ở đây
 * chỉ để trả phí gọi hàm entry (`register_did`, `issue_vc`, `approve_issuer`…).
 */
export async function faucet(address: string, amount = 100_000_000): Promise<bigint> {
  const before = await getBalance(address);
  const res = await fetch(`${CHAIN.faucet}/mint?amount=${amount}&address=${address}`, {
    method: "POST",
  });
  if (!res.ok) {
    throw new ChainError(
      `Faucet từ chối (${res.status}). Thường là do xin quá nhiều lần trong thời gian ngắn — chờ vài phút rồi thử lại.`,
    );
  }
  // Faucet trả về ngay khi đã gửi giao dịch, số dư chưa chắc đã lên.
  for (let i = 0; i < 20; i++) {
    const now = await getBalance(address);
    if (now > before) return now;
    await sleep(700);
  }
  return before;
}

/** Bảo đảm đủ gas trước khi ký; thiếu thì tự xin. Trả về số dư cuối cùng. */
export async function ensureGas(address: string, min = 20_000_000n): Promise<bigint> {
  const bal = await getBalance(address);
  if (bal >= min) return bal;
  return faucet(address);
}

// ---------- Hàm view ----------

export async function view<T = unknown[]>(fn: string, args: unknown[] = []): Promise<T> {
  return node<T>("/view", jsonPost({ function: fn, type_arguments: [], arguments: args }));
}

// ---------- Ký và gửi giao dịch ----------

export interface ChainEvent {
  type: string;
  data: Record<string, unknown>;
}

export interface TxOutcome {
  /** Mã giao dịch thật khi đã lên chuỗi; tham chiếu cục bộ khi chưa nối chuỗi. */
  hash: string;
  /** true = đã thật sự nằm trên chuỗi. false = chỉ ký cục bộ (chế độ diễn tập). */
  submitted: boolean;
  events: ChainEvent[];
  vmStatus: string;
  gasUsed: string;
}

const MAX_GAS = "200000";
const EXPIRY_SECONDS = 120;

let cachedGasPrice: string | null = null;
async function gasUnitPrice(): Promise<string> {
  if (cachedGasPrice) return cachedGasPrice;
  try {
    const r = await node<{ gas_estimate: number }>("/estimate_gas_price");
    cachedGasPrice = String(r.gas_estimate || 100);
  } catch {
    cachedGasPrice = "100";
  }
  return cachedGasPrice;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Ký rồi gửi một lời gọi hàm entry. Chờ tới khi chuỗi xác nhận mới trả về —
 * nhờ vậy tầng trên có `txHash` thật cùng các sự kiện mà hàm đã phát ra, và
 * không bao giờ phải hỏi người dùng mã giao dịch.
 *
 * `live = false` (backend chạy VERIFY_ONCHAIN=false): KHÔNG gửi lên chuỗi, vì
 * ở chế độ đó hoặc chưa có chuỗi, hoặc gói trên chuỗi là bản cũ. Ví vẫn ký đúng
 * nội dung giao dịch đó bằng khoá riêng thật, và ta lấy băm của bản ký làm
 * *tham chiếu cục bộ*. Giao diện phải hiển thị rõ đây chưa phải giao dịch —
 * xem `submitted`.
 */
export async function submitEntry(
  wallet: UnlockedWallet,
  fn: string,
  args: unknown[],
  opts: { live?: boolean; onPhase?: (phase: "signing" | "waiting") => void } = {},
): Promise<TxOutcome> {
  const live = opts.live !== false;
  const phase = opts.onPhase ?? (() => {});

  if (!live) {
    phase("signing");
    return signLocally(wallet, fn, args);
  }
  if (!chainConfigured()) {
    throw new ChainError(
      "Chưa cấu hình địa chỉ hợp đồng (VITE_CONTRACT_ADDRESS). Chạy ./scripts/sync-chain-env.sh rồi khởi động lại giao diện.",
    );
  }

  const payload = {
    type: "entry_function_payload",
    function: fn,
    type_arguments: [] as string[],
    arguments: args,
  };

  const [sequence, price] = await Promise.all([
    getSequenceNumber(wallet.address),
    gasUnitPrice(),
  ]);

  const tx = {
    sender: wallet.address,
    sequence_number: sequence,
    max_gas_amount: MAX_GAS,
    gas_unit_price: price,
    expiration_timestamp_secs: String(Math.floor(Date.now() / 1000) + EXPIRY_SECONDS),
    payload,
  };

  // Fullnode BCS hoá hộ và trả về đúng chuỗi byte cần ký.
  const message = await node<string>(
    "/transactions/encode_submission",
    jsonPost(tx),
  );
  phase("signing");
  const toSign = hexToBytes(message);
  const signature = ed25519.sign(toSign, wallet.keyPair.privateKey);

  const pending = await node<{ hash: string }>(
    "/transactions",
    jsonPost({
      ...tx,
      signature: {
        type: "ed25519_signature",
        public_key: wallet.publicKeyHex,
        signature: toHex(signature),
      },
    }),
  );

  phase("waiting");
  return waitForTx(pending.hash);
}

/** Chờ giao dịch rời khỏi trạng thái pending rồi kiểm tra nó thành công. */
export async function waitForTx(hash: string, timeoutMs = 45_000): Promise<TxOutcome> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const tx = await node<{
      type: string;
      success?: boolean;
      vm_status?: string;
      gas_used?: string;
      events?: ChainEvent[];
    }>(`/transactions/by_hash/${hash}`).catch(() => null);

    if (tx && tx.type !== "pending_transaction") {
      if (!tx.success) {
        throw new ChainError(readableVmStatus(tx.vm_status ?? "giao dịch thất bại"), tx);
      }
      return {
        hash,
        submitted: true,
        events: tx.events ?? [],
        vmStatus: tx.vm_status ?? "Executed successfully",
        gasUsed: tx.gas_used ?? "0",
      };
    }
    if (Date.now() > deadline) {
      throw new ChainError(`Giao dịch ${hash.slice(0, 12)}… chưa được xác nhận sau ${timeoutMs / 1000}s`);
    }
    await sleep(600);
  }
}

/**
 * Chế độ diễn tập: ký thật nhưng không gửi.
 *
 * Tham chiếu trả về là SHA3-256 của nội dung đã ký, đúng dạng 0x + 64 hex mà
 * backend đòi hỏi, nhưng nó KHÔNG phải mã giao dịch — chỗ nào hiển thị cũng
 * phải nói rõ. Có thời điểm ký trong đó nên hai lần gọi giống hệt nhau vẫn ra
 * hai tham chiếu khác nhau.
 */
function signLocally(wallet: UnlockedWallet, fn: string, args: unknown[]): TxOutcome {
  const intent = {
    chainId: CHAIN.chainId,
    sender: wallet.address,
    function: fn,
    arguments: args,
    signedAt: new Date().toISOString(),
  };
  const signature = ed25519.sign(enc.encode(canonicalize(intent)), wallet.keyPair.privateKey);
  return {
    hash: sha3_256Hex({ intent, signature: toHex(signature) }),
    submitted: false,
    events: [],
    vmStatus: "Ký cục bộ — chưa gửi lên chuỗi",
    gasUsed: "0",
  };
}

function hexToBytes(h: string): Uint8Array {
  const c = h.replace(/^0x/, "");
  const out = new Uint8Array(c.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(c.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Mã abort của Move chẳng nói gì với người dùng cuối. Dịch những mã hay gặp
 * sang câu tiếng Việt nói đúng việc phải làm; giữ nguyên phần gốc để còn tra.
 */
function readableVmStatus(raw: string): string {
  const table: [RegExp, string][] = [
    [/NOT_ROOT_ADMIN|0x1f4\b/i, "Chỉ tài khoản root mới gọi được hàm này"],
    [/ADMIN_NOT_ACTIVE/i, "Địa chỉ này không phải admin đang hoạt động"],
    [/ISSUER_NOT_ACTIVE|NOT_ACTIVE_ISSUER/i, "Quyền issuer chưa được cấp hoặc đã hết hiệu lực"],
    [/OWNER_NOT_EXISTS|DID_NOT_FOUND/i, "Địa chỉ này chưa đăng ký DID trên chuỗi"],
    [/DID_NOT_ACTIVE/i, "DID của địa chỉ này đang không hoạt động"],
    [/ALREADY_EXISTS/i, "Bản ghi đã tồn tại trên chuỗi"],
    [/UNAUTHORIZED_VC_TYPE|0x3f5\b/i, "Loại văn bằng vượt quá phạm vi được uỷ quyền"],
    [/PROTECTED_TARGET|0x3fa\b/i, "Không được tác động lên DID của root hoặc admin khác"],
    [/DID_NOT_BOUND_TO_OWNER|0x7db\b/i, "Chuỗi DID phải kết thúc bằng chính địa chỉ ví của bạn"],
    [/OWNER_LOCKED|0x7dc\b/i, "DID do chính chủ tự khoá — chỉ chủ sở hữu mở lại được"],
    [/SELF_ISSUE|0xbc2\b/i, "Đơn vị cấp không được tự cấp văn bằng cho chính mình"],
    [/INSUFFICIENT_BALANCE|OUT_OF_GAS/i, "Không đủ gas — bấm “Nhận token” rồi thử lại"],
    [/SEQUENCE_NUMBER_TOO_OLD/i, "Số thứ tự giao dịch đã cũ — thử lại"],
  ];
  for (const [re, msg] of table) if (re.test(raw)) return `${msg} (${raw})`;
  return raw;
}

// ---------- Đọc sự kiện ----------

/** Lấy một trường số từ sự kiện có tên khớp — ví dụ `VCIssuedEvent.id`. */
export function eventNumber(out: TxOutcome, eventName: string, field = "id"): number | null {
  const ev = out.events.find((e) => typeof e.type === "string" && e.type.includes(eventName));
  const raw = ev?.data?.[field];
  if (raw === undefined || raw === null) return null;
  const n = Number(raw);
  return Number.isFinite(n) ? n : null;
}

/**
 * Số hiệu VC do chuỗi cấp, đọc từ `VCIssuedEvent`.
 *
 * Trước đây giao diện ghi cứng `onChainVcId: 0` vì nó không tự gửi giao dịch
 * nên chẳng bao giờ thấy phản hồi — một trường bịa nằm im trong CSDL. Nay tự
 * gửi thì đọc được số thật.
 */
export const vcIdFromEvents = (out: TxOutcome): number | null => eventNumber(out, "VCIssuedEvent", "id");
