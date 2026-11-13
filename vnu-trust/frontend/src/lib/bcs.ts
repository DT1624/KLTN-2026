/**
 * BCS hoá RawTransaction cho lời gọi hàm entry — đủ để VÍ TỰ KIỂM thông điệp
 * mà fullnode trả về từ /transactions/encode_submission trước khi ký (W-01).
 *
 * Vì sao cần: trước đây ví ký nguyên chuỗi byte fullnode đưa. Một fullnode ác ý
 * (hay bị chiếm, hay VITE_CHAIN_FULLNODE trỏ nhầm) trả thông điệp của một giao
 * dịch KHÁC — propose_root(kẻ tấn công), chuyển token… — là ví ký mù rồi kẻ đó
 * tự gửi bằng chữ ký vừa lấy. Đối chiếu với /simulate không cứu được vì cùng
 * một node nói dối được ở cả hai đường. Tự dựng lại byte thì cứu được.
 *
 * Không dùng Aptos SDK (quyết định #4): một hàm entry chỉ cần ba kiểu tham số.
 */
import { sha3_256 } from "@noble/hashes/sha3";

/** "u64s" = vector<u64> (thao tác theo lô C2). */
export type MoveParam = "address" | "u64" | "bytes" | "u64s";

/**
 * Kiểu tham số (bỏ signer) của mọi hàm entry mà giao diện gọi, theo mã Move.
 * `frontend/scripts/bcs-check.mjs` đối chiếu bảng này với contracts/sources.
 */
export const ENTRY_PARAMS: Record<string, MoveParam[]> = {
  "did_registry::register_did": ["bytes", "bytes", "bytes"],
  "did_registry::update_did_document": ["bytes", "bytes", "u64"],
  "did_registry::suspend_own_did": [],
  "did_registry::reactivate_own_did": [],
  "did_registry::deactivate_did": [],
  "authority::propose_root": ["address"],
  "authority::accept_root": [],
  "authority::cancel_root_transfer": [],
  "authority::grant_admin": ["address"],
  "authority::revoke_admin": ["address", "bytes"],
  "authority::approve_issuer": ["address", "u64", "bytes", "bytes", "u64"],
  "authority::suspend_issuer": ["address", "bytes"],
  "authority::reactivate_issuer": ["address", "bytes"],
  "authority::revoke_issuer": ["address", "bytes"],
  "authority::admin_suspend_did": ["address", "bytes"],
  "authority::admin_reactivate_did": ["address", "bytes"],
  "authority::admin_revoke_did": ["address", "bytes"],
  "vc_registry::issue_vc": ["address", "u64", "bytes", "bytes", "bytes", "u64"],
  "vc_registry::suspend_vc": ["u64", "bytes"],
  "vc_registry::revoke_vc": ["u64", "bytes"],
  "vc_registry::admin_suspend_vc": ["u64", "bytes"],
  "vc_registry::admin_reinstate_vc": ["u64", "bytes"],
  "vc_registry::admin_revoke_vc": ["u64", "bytes"],
  // Nâng cấp 13/11: C2 (theo lô) và C3 (cấp lại).
  "vc_registry::admin_suspend_vcs": ["u64s", "bytes"],
  "vc_registry::admin_revoke_vcs": ["u64s", "bytes"],
  "vc_registry::delegator_suspend_vcs": ["u64s", "bytes"],
  "vc_registry::delegator_revoke_vcs": ["u64s", "bytes"],
  "vc_registry::reissue_vc": ["u64", "address", "u64", "bytes", "bytes", "bytes", "u64"],
  "vc_registry::admin_link_replacement": ["u64", "u64"],
};

/** Hex nghiêm ngặt: độ dài chẵn, chỉ ký tự hex — không lặng lẽ biến ký tự lạ thành 0. */
export function hexToBytes(h: string): Uint8Array {
  const c = h.replace(/^0x/i, "");
  if (c.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(c)) throw new Error(`Chuỗi hex không hợp lệ: ${h.slice(0, 20)}…`);
  const out = new Uint8Array(c.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(c.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function uleb(n: number): number[] {
  const out: number[] = [];
  do {
    let b = n & 0x7f;
    n >>>= 7;
    if (n !== 0) b |= 0x80;
    out.push(b);
  } while (n !== 0);
  return out;
}
function u64(v: string | number | bigint): number[] {
  let x = BigInt(v);
  if (x < 0n || x >= 1n << 64n) throw new Error(`u64 ngoài khoảng: ${v}`);
  const out: number[] = [];
  for (let i = 0; i < 8; i++) { out.push(Number(x & 0xffn)); x >>= 8n; }
  return out;
}
function address(a: string): number[] {
  const c = a.replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{1,64}$/.test(c)) throw new Error(`Địa chỉ không hợp lệ: ${a}`);
  return Array.from(hexToBytes(c.padStart(64, "0")));
}
const str = (s: string) => { const b = new TextEncoder().encode(s); return [...uleb(b.length), ...b]; };

function u64s(v: unknown): number[] {
  if (!Array.isArray(v)) throw new Error("vector<u64> phải là mảng");
  return [...uleb(v.length), ...v.flatMap((x) => u64(String(x)))];
}

function arg(kind: MoveParam, v: unknown): number[] {
  const inner = kind === "address" ? address(String(v))
    : kind === "u64" ? u64(String(v))
      : kind === "u64s" ? u64s(v)
        : (() => { const b = hexToBytes(String(v)); return [...uleb(b.length), ...b]; })();
  return [...uleb(inner.length), ...inner];
}

export interface EntryTx {
  sender: string;
  sequence_number: string;
  max_gas_amount: string;
  gas_unit_price: string;
  expiration_timestamp_secs: string;
  payload: { function: string; type_arguments: string[]; arguments: unknown[] };
}

/** Thông điệp cần ký = SHA3-256("APTOS::RawTransaction") ‖ BCS(RawTransaction). */
export function signingMessage(tx: EntryTx, chainId: number): Uint8Array {
  const [addr, mod, fn, ...rest] = tx.payload.function.split("::");
  if (!addr || !mod || !fn || rest.length) throw new Error(`Tên hàm không hợp lệ: ${tx.payload.function}`);
  const kinds = ENTRY_PARAMS[`${mod}::${fn}`];
  if (!kinds) throw new Error(`Ví không biết kiểu tham số của ${mod}::${fn} — từ chối ký`);
  if (tx.payload.type_arguments.length) throw new Error("Hàm entry của hợp đồng không có tham số kiểu");
  if (kinds.length !== tx.payload.arguments.length) {
    throw new Error(`${mod}::${fn} cần ${kinds.length} tham số, nhận ${tx.payload.arguments.length}`);
  }
  const bytes = [
    ...address(tx.sender),
    ...u64(tx.sequence_number),
    ...uleb(2), // TransactionPayload::EntryFunction
    ...address(addr), ...str(mod), ...str(fn),
    ...uleb(0), // không có type argument
    ...uleb(kinds.length), ...kinds.flatMap((k, i) => arg(k, tx.payload.arguments[i])),
    ...u64(tx.max_gas_amount),
    ...u64(tx.gas_unit_price),
    ...u64(tx.expiration_timestamp_secs),
    chainId & 0xff,
  ];
  const prefix = sha3_256(new TextEncoder().encode("APTOS::RawTransaction"));
  const out = new Uint8Array(prefix.length + bytes.length);
  out.set(prefix, 0);
  out.set(bytes, prefix.length);
  return out;
}
