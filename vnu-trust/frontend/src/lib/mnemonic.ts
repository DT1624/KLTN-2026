/**
 * KHÔI PHỤC VÍ BẰNG CỤM TỪ GHI NHỚ (BIP39 + SLIP-0010)
 *
 * Bài toán: người dùng muốn đăng nhập trên máy khác, nhưng tài khoản KHÔNG được
 * lưu ở cơ sở dữ liệu và khoá riêng KHÔNG được rời khỏi trình duyệt.
 *
 * Lời giải: khoá không cần lưu ở đâu cả — nó được SINH LẠI một cách tất định từ
 * 12 từ tiếng Anh mà người dùng ghi nhớ.
 *
 *   12 từ  --BIP39-->  seed 64 byte  --SLIP-0010-->  khoá riêng Ed25519
 *                                                    -> khoá công khai -> địa chỉ ví
 *
 * Toàn bộ chuỗi này chạy trong trình duyệt. Máy chủ chỉ lưu phần CÔNG KHAI
 * (địa chỉ, khoá công khai, DID, vai trò, tên hiển thị) — đúng vai trò một cuốn
 * danh bạ, không phải nơi giữ tài khoản. Không có mật khẩu băm, không có khoá
 * riêng, không có gì để đánh cắp mà đăng nhập thay người dùng được.
 *
 * Đường dẫn m/44'/637'/0'/0'/0' là chuẩn của Aptos (coin type 637), nên cùng một
 * cụm từ cũng nhập được vào ví Petra. Phép dẫn xuất đã đối chiếu trùng khớp
 * tuyệt đối với @aptos-labs/ts-sdk.
 */
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha512";

/** Đường dẫn dẫn xuất chuẩn Aptos/Movement. */
export const APTOS_PATH = "m/44'/637'/0'/0'/0'";

const HARDENED = 0x80000000;

interface Node {
  key: Uint8Array;
  chainCode: Uint8Array;
}

function master(seed: Uint8Array): Node {
  const I = hmac(sha512, new TextEncoder().encode("ed25519 seed"), seed);
  return { key: I.slice(0, 32), chainCode: I.slice(32) };
}

/**
 * SLIP-0010 chỉ định nghĩa nhánh hardened cho ed25519 — không có nhánh thường,
 * vì đường cong này không hỗ trợ dẫn xuất khoá công khai độc lập.
 */
function child(parent: Node, index: number): Node {
  const data = new Uint8Array(37);
  data[0] = 0x00;
  data.set(parent.key, 1);
  new DataView(data.buffer).setUint32(33, index >>> 0, false);
  const I = hmac(sha512, parent.chainCode, data);
  return { key: I.slice(0, 32), chainCode: I.slice(32) };
}

/** Sinh 12 từ mới từ nguồn ngẫu nhiên của hệ điều hành (128 bit entropy). */
export function newMnemonic(): string {
  return generateMnemonic(wordlist, 128);
}

export function isValidMnemonic(phrase: string): boolean {
  return validateMnemonic(normalizeMnemonic(phrase), wordlist);
}

/** Chuẩn hoá: gộp khoảng trắng thừa, bỏ hoa/thường — người dùng gõ tay hay sai chỗ này. */
export function normalizeMnemonic(phrase: string): string {
  return phrase.trim().toLowerCase().split(/\s+/).join(" ");
}

/** Sinh lại khoá riêng từ cụm từ. Cùng cụm từ luôn cho cùng một khoá. */
export function privateKeyFromMnemonic(phrase: string, path = APTOS_PATH): Uint8Array {
  const normalized = normalizeMnemonic(phrase);
  if (!validateMnemonic(normalized, wordlist)) {
    throw new Error("Cụm từ ghi nhớ không hợp lệ — kiểm tra lại chính tả và thứ tự các từ");
  }
  const seed = mnemonicToSeedSync(normalized);
  let node = master(seed);
  for (const seg of path.split("/").slice(1)) {
    const hardened = seg.endsWith("'");
    const idx = Number.parseInt(hardened ? seg.slice(0, -1) : seg, 10);
    if (!Number.isInteger(idx) || idx < 0) throw new Error(`Đường dẫn dẫn xuất không hợp lệ: ${path}`);
    node = child(node, idx + (hardened ? HARDENED : 0));
  }
  return node.key;
}

/** Kiểm tra người dùng đã chép đúng cụm từ chưa, bằng cách hỏi lại vài từ. */
export function pickVerificationIndices(count = 3, total = 12): number[] {
  const picked = new Set<number>();
  while (picked.size < count) {
    picked.add(Math.floor(Math.random() * total));
  }
  return [...picked].sort((a, b) => a - b);
}
