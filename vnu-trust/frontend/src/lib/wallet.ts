/**
 * VÍ PHI LƯU KÝ (non-custodial) — khoá riêng KHÔNG BAO GIỜ rời khỏi trình duyệt.
 *
 * Mô hình bảo mật:
 *  1. Cặp khoá Ed25519 sinh ngay trong trình duyệt bằng nguồn ngẫu nhiên của
 *     hệ điều hành (crypto.getRandomValues qua Aptos SDK).
 *  2. Khoá riêng được mã hoá AES-256-GCM. Khoá mã hoá dẫn xuất từ mật khẩu
 *     người dùng bằng PBKDF2-SHA256 với 600.000 vòng lặp (khuyến nghị OWASP
 *     2023) và muối ngẫu nhiên 16 byte cho mỗi ví.
 *  3. Chỉ bản mã (ciphertext + salt + iv) được lưu vào IndexedDB. Máy chủ
 *     không nhận được khoá riêng lẫn mật khẩu — chỉ nhận khoá công khai và
 *     chữ ký.
 *  4. Khoá riêng ở dạng rõ chỉ tồn tại trong bộ nhớ khi ví đang mở, và bị
 *     xoá khi khoá ví, khi hết thời gian chờ, hoặc khi đóng tab.
 *  5. Đăng nhập theo cơ chế thách thức - đáp ứng: máy chủ gửi nonce dùng một
 *     lần, trình duyệt ký, máy chủ kiểm bằng khoá công khai đã đăng ký.
 *     Không có mật khẩu nào truyền qua mạng.
 *
 * Vì sao cách này an toàn nhất cho người sở hữu văn bằng: kể cả khi máy chủ
 * bị chiếm quyền hoàn toàn, kẻ tấn công vẫn không thể ký thay người dùng,
 * không thể tạo VP giả, và không đọc được khoá riêng của bất kỳ ai.
 */
import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";
import { newMnemonic, privateKeyFromMnemonic, isValidMnemonic } from "./mnemonic";

/**
 * Mã hoá Ed25519 dùng trực tiếp @noble thay vì toàn bộ Aptos SDK: gói SDK nặng
 * ~4,7 MB trong khi ở đây chỉ cần sinh khoá, ký và dẫn xuất địa chỉ. Kết quả đã
 * được đối chiếu trùng khớp tuyệt đối với SDK (địa chỉ, khoá công khai, chữ ký).
 */
const hex = (b: Uint8Array) => "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (h: string) => {
  const c = h.replace(/^0x/, "");
  if (c.length % 2 !== 0 || /[^0-9a-fA-F]/.test(c)) throw new Error("Chuỗi hex không hợp lệ");
  const out = new Uint8Array(c.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(c.slice(i * 2, i * 2 + 2), 16);
  return out;
};

/** Địa chỉ Aptos/Movement cho sơ đồ một chữ ký Ed25519 = sha3_256(pubkey ‖ 0x00). */
function deriveAddress(publicKey: Uint8Array): string {
  return hex(sha3_256(new Uint8Array([...publicKey, 0x00])));
}

/** Cặp khoá đang mở. Khoá riêng chỉ nằm trong bộ nhớ của tab này. */
export interface KeyPair {
  privateKey: Uint8Array;
  publicKeyHex: string;
  address: string;
}

function keyPairFromPrivate(priv: Uint8Array): KeyPair {
  if (priv.length !== 32) throw new Error("Khoá riêng Ed25519 phải dài đúng 32 byte");
  const pub = ed25519.getPublicKey(priv);
  return { privateKey: priv, publicKeyHex: hex(pub), address: deriveAddress(pub) };
}

const DB_NAME = "vnu-trust-wallet";
const DB_VERSION = 1;
const STORE = "keystores";
const PBKDF2_ITERATIONS = 600_000;

export interface StoredKeystore {
  /** Khoá chính trong IndexedDB — địa chỉ ví. */
  address: string;
  publicKeyHex: string;
  did: string;
  role: Role;
  label: string;
  /** Bản mã của khoá riêng, base64. */
  ciphertext: string;
  salt: string;
  iv: string;
  createdAt: string;
  kdf: { name: "PBKDF2"; hash: "SHA-256"; iterations: number };
}

export type Role = "root" | "admin" | "issuer" | "holder" | "verifier";

export interface UnlockedWallet {
  address: string;
  publicKeyHex: string;
  did: string;
  role: Role;
  label: string;
  /** Chỉ tồn tại trong bộ nhớ. Không bao giờ tuần tự hoá ra ngoài. */
  keyPair: KeyPair;
  /** Chỉ có giá trị ngay sau khi tạo ví mới, để hiển thị một lần rồi thôi. */
  mnemonic?: string;
}

// ---------- IndexedDB ----------

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: "address" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("Không mở được IndexedDB"));
  });
}

async function tx<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await openDb();
  return new Promise<T>((resolve, reject) => {
    const t = db.transaction(STORE, mode);
    const req = fn(t.objectStore(STORE));
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error("Thao tác IndexedDB thất bại"));
    t.oncomplete = () => db.close();
  });
}

export const listKeystores = () => tx<StoredKeystore[]>("readonly", (s) => s.getAll());
export const getKeystore = (address: string) =>
  tx<StoredKeystore | undefined>("readonly", (s) => s.get(address));
export const deleteKeystore = (address: string) =>
  tx<undefined>("readwrite", (s) => s.delete(address));

/**
 * Cập nhật vai trò đã lưu trong ví theo hồ sơ trên máy chủ.
 *
 * Vai trò trong ví là thứ người dùng tự khai lúc tạo, còn vai trò thật thì đổi
 * theo quyền được cấp trên chuỗi (được phong admin, nhận quyền root…). Không
 * đồng bộ thì menu và mọi chặn phía giao diện cứ bám mãi vào vai trò cũ.
 */
export async function updateKeystoreRole(address: string, role: Role): Promise<void> {
  const rec = await getKeystore(address);
  if (!rec || rec.role === role) return;
  await tx("readwrite", (s) => s.put({ ...rec, role }));
}

// ---------- Mã hoá ----------

const b64 = {
  enc: (b: ArrayBuffer | Uint8Array) =>
    btoa(String.fromCharCode(...new Uint8Array(b instanceof Uint8Array ? b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength) : b))),
  dec: (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
};

async function deriveKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: salt as BufferSource, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

export function checkPassphraseStrength(p: string): { ok: boolean; message: string } {
  if (p.length < 10) return { ok: false, message: "Mật khẩu phải dài ít nhất 10 ký tự" };
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((r) => r.test(p)).length;
  if (classes < 3) {
    return { ok: false, message: "Cần ít nhất 3 trong 4 loại: chữ thường, chữ hoa, số, ký tự đặc biệt" };
  }
  return { ok: true, message: "Mật khẩu đạt yêu cầu" };
}

// ---------- Tạo / mở / khoá ví ----------

export interface CreateWalletInput {
  passphrase: string;
  role: Role;
  label: string;
  didMethod?: string;
  /** Bỏ trống thì sinh cụm từ mới. Truyền vào khi khôi phục từ 12 từ có sẵn. */
  mnemonic?: string;
}

export async function createWallet(input: CreateWalletInput): Promise<UnlockedWallet> {
  const strength = checkPassphraseStrength(input.passphrase);
  if (!strength.ok) throw new Error(strength.message);

  // Sinh khoá TỪ cụm từ ghi nhớ chứ không ngẫu nhiên trực tiếp: nhờ vậy người
  // dùng chỉ cần 12 từ là khôi phục được ví trên bất kỳ thiết bị nào, không
  // cần chép tệp và không cần máy chủ lưu gì.
  const mnemonic = input.mnemonic ?? newMnemonic();
  const kp = keyPairFromPrivate(privateKeyFromMnemonic(mnemonic));
  const address = kp.address;
  const did = `${input.didMethod ?? "did:vnu"}:${input.role}:${address}`;

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(input.passphrase, salt);

  // Khoá riêng dạng hex -> mã hoá. Không ghi bản rõ đi đâu cả.
  const privHex = hex(kp.privateKey);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    key,
    new TextEncoder().encode(privHex),
  );

  const record: StoredKeystore = {
    address,
    publicKeyHex: kp.publicKeyHex,
    did,
    role: input.role,
    label: input.label,
    ciphertext: b64.enc(ciphertext),
    salt: b64.enc(salt),
    iv: b64.enc(iv),
    createdAt: new Date().toISOString(),
    kdf: { name: "PBKDF2", hash: "SHA-256", iterations: PBKDF2_ITERATIONS },
  };
  await tx("readwrite", (s) => s.put(record));

  return {
    address,
    publicKeyHex: record.publicKeyHex,
    did,
    role: input.role,
    label: input.label,
    keyPair: kp,
    /** Chỉ trả về đúng lúc vừa tạo, để hiển thị cho người dùng chép lại. KHÔNG lưu. */
    mnemonic,
  };
}

export async function unlockWallet(address: string, passphrase: string): Promise<UnlockedWallet> {
  const rec = await getKeystore(address);
  if (!rec) throw new Error("Không tìm thấy ví trong trình duyệt này");

  const key = await deriveKey(passphrase, b64.dec(rec.salt));
  let privHex: string;
  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64.dec(rec.iv) as BufferSource },
      key,
      b64.dec(rec.ciphertext) as BufferSource,
    );
    privHex = new TextDecoder().decode(plain);
  } catch {
    // AES-GCM thất bại xác thực -> mật khẩu sai hoặc dữ liệu bị sửa.
    throw new Error("Mật khẩu không đúng");
  }

  const kp = keyPairFromPrivate(unhex(privHex));
  if (kp.address !== rec.address || kp.publicKeyHex !== rec.publicKeyHex) {
    throw new Error("Dữ liệu ví không nhất quán — địa chỉ không khớp khoá");
  }

  return {
    address: rec.address,
    publicKeyHex: rec.publicKeyHex,
    did: rec.did,
    role: rec.role,
    label: rec.label,
    keyPair: kp,
  };
}

/** Nhập lại ví từ khoá riêng (khôi phục trên máy khác). */
export async function importWallet(
  privateKeyHex: string,
  passphrase: string,
  role: Role,
  label: string,
  didMethod = "did:vnu",
): Promise<UnlockedWallet> {
  const strength = checkPassphraseStrength(passphrase);
  if (!strength.ok) throw new Error(strength.message);

  let kp: KeyPair;
  try {
    kp = keyPairFromPrivate(unhex(privateKeyHex.trim()));
  } catch {
    throw new Error("Khoá riêng không hợp lệ");
  }

  const address = kp.address;
  if (await getKeystore(address)) throw new Error("Ví này đã có sẵn trong trình duyệt");

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    key,
    new TextEncoder().encode(privateKeyHex.trim()),
  );

  const record: StoredKeystore = {
    address,
    publicKeyHex: kp.publicKeyHex,
    did: `${didMethod}:${role}:${address}`,
    role,
    label,
    ciphertext: b64.enc(ciphertext),
    salt: b64.enc(salt),
    iv: b64.enc(iv),
    createdAt: new Date().toISOString(),
    kdf: { name: "PBKDF2", hash: "SHA-256", iterations: PBKDF2_ITERATIONS },
  };
  await tx("readwrite", (s) => s.put(record));

  return { address, publicKeyHex: record.publicKeyHex, did: record.did, role, label, keyPair: kp };
}

/**
 * Khôi phục ví từ 12 từ — trên thiết bị mới, hoặc trên chính máy này khi quên
 * mật khẩu.
 *
 * Khoá được sinh lại từ chính cụm từ, nên ra đúng địa chỉ cũ. Cụm từ là bằng
 * chứng sở hữu MẠNH HƠN mật khẩu, nên nếu máy này đã có ví đó thì ghi đè bằng
 * mật khẩu mới (đây chính là đường "quên mật khẩu"): không mất gì, vì khoá sinh
 * lại y hệt. Trước đây trường hợp này báo "hãy dùng Mở ví" — mà Mở ví lại cần
 * đúng mật khẩu đã quên, nên người dùng phải xoá ví (kèm cảnh báo "không khôi
 * phục được") rồi mới khôi phục lại.
 *
 * `serverDid`: DID mà máy chủ đã ghi danh cho địa chỉ này. Phải dùng đúng chuỗi
 * đó: DID gắn vai trò LÚC ĐĂNG KÝ, còn `role` là vai trò HIỆN TẠI — holder được
 * phong issuer mà dựng lại DID theo vai trò mới thì ví mang DID sai và mọi thao
 * tác DID sau đó bị máy chủ từ chối ("DID không khớp tài khoản").
 */
export async function restoreFromMnemonic(
  mnemonic: string,
  passphrase: string,
  role: Role,
  label: string,
  didMethod = "did:vnu",
  serverDid?: string,
): Promise<UnlockedWallet> {
  if (!isValidMnemonic(mnemonic)) {
    throw new Error("Cụm từ ghi nhớ không hợp lệ — kiểm tra lại chính tả và thứ tự các từ");
  }
  const strength = checkPassphraseStrength(passphrase);
  if (!strength.ok) throw new Error(strength.message);

  const kp = keyPairFromPrivate(privateKeyFromMnemonic(mnemonic));
  // Ví đã có trên máy này: giữ tên hiển thị cục bộ (máy chủ không trả tên qua
  // tuyến công khai — P-05) rồi ghi đè bằng mật khẩu mới.
  const existing = await getKeystore(kp.address);
  const keepLabel = existing?.label ?? label;
  const did = serverDid && serverDid.endsWith(kp.address) ? serverDid : `${didMethod}:${role}:${kp.address}`;

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    key,
    new TextEncoder().encode(hex(kp.privateKey)),
  );

  const record: StoredKeystore = {
    address: kp.address,
    publicKeyHex: kp.publicKeyHex,
    did,
    role,
    label: keepLabel,
    ciphertext: b64.enc(ciphertext),
    salt: b64.enc(salt),
    iv: b64.enc(iv),
    createdAt: new Date().toISOString(),
    kdf: { name: "PBKDF2", hash: "SHA-256", iterations: PBKDF2_ITERATIONS },
  };
  await tx("readwrite", (s) => s.put(record));

  return {
    address: kp.address,
    publicKeyHex: kp.publicKeyHex,
    did: record.did,
    role,
    label: keepLabel,
    keyPair: kp,
  };
}

/**
 * Xem trước ví mà một cụm từ sẽ sinh ra, KHÔNG lưu gì xuống máy.
 * Dùng để hỏi máy chủ xem địa chỉ này đã đăng ký chưa và với vai trò nào,
 * trước khi bắt người dùng chọn lại vai trò và tên hiển thị.
 */
export function previewFromMnemonic(mnemonic: string): { address: string; publicKeyHex: string } {
  const kp = keyPairFromPrivate(privateKeyFromMnemonic(mnemonic));
  return { address: kp.address, publicKeyHex: kp.publicKeyHex };
}

/** Xuất bản sao lưu — vẫn ở dạng đã mã hoá, an toàn để lưu trữ ngoài. */
export async function exportKeystore(address: string): Promise<Blob> {
  const rec = await getKeystore(address);
  if (!rec) throw new Error("Không tìm thấy ví");
  return new Blob([JSON.stringify(rec, null, 2)], { type: "application/json" });
}

export async function importKeystoreFile(json: string): Promise<StoredKeystore> {
  const rec = JSON.parse(json) as StoredKeystore;
  const required: (keyof StoredKeystore)[] = ["address", "publicKeyHex", "ciphertext", "salt", "iv"];
  for (const f of required) {
    if (!rec[f]) throw new Error(`Tệp sao lưu thiếu trường "${String(f)}"`);
  }
  await tx("readwrite", (s) => s.put(rec));
  return rec;
}

// ---------- Ký ----------

export function signMessage(wallet: UnlockedWallet, message: string): string {
  return hex(ed25519.sign(new TextEncoder().encode(message), wallet.keyPair.privateKey));
}

/**
 * Tuần tự hoá tất định — phải khớp hàm canonicalize() của backend, nếu không
 * hash hai bên sẽ lệch và mọi phép kiểm tra toàn vẹn đều thất bại.
 */
export function canonicalize(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  const obj = value as Record<string, unknown>;
  return (
    "{" +
    Object.keys(obj)
      .sort()
      .map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k]))
      .join(",") +
    "}"
  );
}

/**
 * SHA3-256 của bản tuần tự hoá tất định, trả về "0x…" giống backend.
 * WebCrypto không có SHA3 nên dùng @noble/hashes (vốn đã là phụ thuộc của Aptos SDK).
 */
export function sha3_256Hex(value: unknown): string {
  const data = new TextEncoder().encode(canonicalize(value));
  return "0x" + Array.from(sha3_256(data)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function verifySignature(publicKeyHex: string, message: string, signatureHex: string): boolean {
  try {
    return ed25519.verify(
      unhex(signatureHex),
      new TextEncoder().encode(message),
      unhex(publicKeyHex),
    );
  } catch {
    return false;
  }
}

/** Xuất khoá riêng dạng hex — chỉ dùng khi người dùng chủ động yêu cầu sao lưu. */
export function exportPrivateKeyHex(wallet: UnlockedWallet): string {
  return hex(wallet.keyPair.privateKey);
}
