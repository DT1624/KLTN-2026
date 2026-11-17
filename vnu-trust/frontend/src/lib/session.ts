/**
 * GIỮ PHIÊN VÍ QUA F5 (tải lại trang trong cùng tab) mà không lưu khoá riêng dạng rõ.
 *
 * Mô hình đe doạ:
 *  - Khi mở ví, khoá riêng được bọc bằng một CryptoKey AES-256-GCM `extractable: false`
 *    (không xuất được, kể cả bởi mã trong trang), AAD = địa chỉ. Bản bọc + CryptoKey nằm
 *    ở IndexedDB RIÊNG (`vnu-trust-session`); sessionStorage chỉ giữ `sid` ngẫu nhiên.
 *  - Chỉ tab có đúng `sid` mới khôi phục được; tab khác, tab mới, đóng tab (sessionStorage
 *    mất) thì bản ghi mồ côi và bị dọn.
 *  - Hạn của bản ghi = hạn tự khoá còn lại (15 phút không thao tác); quá hạn thì xoá.
 *  - Không có khoá riêng, mnemonic hay mật khẩu dạng rõ ở bất kỳ kho lưu trữ nào.
 *  - XSS trong tab đang mở vốn đã truy cập được RAM của ví nên cách này không mở rộng
 *    bề mặt tấn công đáng kể.
 *  - Giới hạn chấp nhận: tính năng "nhân bản tab" của trình duyệt có thể chép sessionStorage
 *    (kèm sid) sang tab mới, tab đó khôi phục được trong hạn còn lại.
 */
import { ed25519 } from "@noble/curves/ed25519";
import type { UnlockedWallet } from "./wallet";

export interface SessionRecord {
  sessionId: string;
  address: string;
  publicKeyHex: string;
  meta: Record<string, unknown>;
  wrapped: Uint8Array;
  iv: Uint8Array;
  key: CryptoKey;
  expiresAt: number;
}

export interface SessionStore {
  get(id: string): Promise<SessionRecord | undefined>;
  put(r: SessionRecord): Promise<void>;
  delete(id: string): Promise<void>;
  all(): Promise<SessionRecord[]>;
}

export interface SidStore {
  get(): string | null;
  set(v: string): void;
  clear(): void;
}

const enc = new TextEncoder();
const toHex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");

export function createKeySession(deps: { store: SessionStore; sid: SidStore; now?: () => number }) {
  const { store, sid } = deps;
  const now = deps.now ?? (() => Date.now());

  async function save(wallet: UnlockedWallet, expiresAt: number): Promise<void> {
    const old = sid.get();
    if (old) await store.delete(old);

    const id = toHex(crypto.getRandomValues(new Uint8Array(16)));
    const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const wrapped = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv as BufferSource, additionalData: enc.encode(wallet.address) as BufferSource },
        key,
        wallet.keyPair.privateKey as BufferSource,
      ),
    );
    // Mọi trường công khai ngoài keyPair; tuyệt đối không mnemonic.
    const { keyPair: _kp, mnemonic: _m, ...meta } = wallet;
    void _kp;
    void _m;
    sid.set(id);
    await store.put({
      sessionId: id,
      address: wallet.address,
      publicKeyHex: wallet.keyPair.publicKeyHex,
      meta: meta as Record<string, unknown>,
      wrapped,
      iv,
      key,
      expiresAt,
    });
  }

  async function restore(): Promise<{ wallet: UnlockedWallet; expiresAt: number } | null> {
    const id = sid.get();
    if (!id) return null;
    const rec = await store.get(id);
    if (!rec) return null;
    if (now() > rec.expiresAt) {
      await store.delete(id);
      return null;
    }
    try {
      const plain = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: rec.iv as BufferSource, additionalData: enc.encode(rec.address) as BufferSource },
        rec.key,
        rec.wrapped as BufferSource,
      );
      const priv = new Uint8Array(plain);
      const pub = "0x" + toHex(ed25519.getPublicKey(priv));
      if (pub.toLowerCase() !== String(rec.publicKeyHex).toLowerCase()) {
        priv.fill(0);
        await store.delete(id);
        return null;
      }
      const wallet = {
        ...rec.meta,
        address: rec.address,
        publicKeyHex: rec.publicKeyHex,
        keyPair: { privateKey: priv, publicKeyHex: rec.publicKeyHex, address: rec.address },
      } as unknown as UnlockedWallet;
      return { wallet, expiresAt: rec.expiresAt };
    } catch {
      try { await store.delete(id); } catch { /* bỏ qua */ }
      return null;
    }
  }

  async function touch(expiresAt: number): Promise<void> {
    const id = sid.get();
    if (!id) return;
    const rec = await store.get(id);
    if (!rec) return;
    await store.put({ ...rec, expiresAt });
  }

  async function clear(): Promise<void> {
    const id = sid.get();
    if (id) await store.delete(id);
    sid.clear();
  }

  async function purgeOrphans(): Promise<void> {
    const id = sid.get();
    const t = now();
    for (const r of await store.all()) {
      if (r.sessionId !== id || t > r.expiresAt) await store.delete(r.sessionId);
    }
  }

  return { save, restore, touch, clear, purgeOrphans };
}

// ---------- Kho thật: IndexedDB riêng + sessionStorage ----------

const DB_NAME = "vnu-trust-session";
const STORE = "sessions";

export function idbSessionStore(): SessionStore {
  let dbp: Promise<IDBDatabase | null> | null = null;
  const open = (): Promise<IDBDatabase | null> => {
    if (!dbp) {
      dbp = new Promise((resolve) => {
        try {
          const req = indexedDB.open(DB_NAME, 1);
          req.onupgradeneeded = () => {
            if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE, { keyPath: "sessionId" });
          };
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => resolve(null);
          req.onblocked = () => resolve(null);
        } catch {
          resolve(null);
        }
      });
    }
    return dbp;
  };
  const run = async <T>(mode: IDBTransactionMode, fallback: T, fn: (s: IDBObjectStore) => IDBRequest): Promise<T> => {
    const db = await open();
    if (!db) return fallback;
    return new Promise<T>((resolve) => {
      try {
        const req = fn(db.transaction(STORE, mode).objectStore(STORE));
        req.onsuccess = () => resolve((req.result ?? fallback) as T);
        req.onerror = () => resolve(fallback);
      } catch {
        resolve(fallback);
      }
    });
  };
  return {
    get: (id) => run<SessionRecord | undefined>("readonly", undefined, (s) => s.get(id)),
    put: (r) => run<void>("readwrite", undefined, (s) => s.put(r)),
    delete: (id) => run<void>("readwrite", undefined, (s) => s.delete(id)),
    all: () => run<SessionRecord[]>("readonly", [], (s) => s.getAll()),
  };
}

const SID_KEY = "vnu_trust_sid";

export function sessionStorageSid(): SidStore {
  return {
    get: () => {
      try { return sessionStorage.getItem(SID_KEY); } catch { return null; }
    },
    set: (v) => {
      try { sessionStorage.setItem(SID_KEY, v); } catch { /* chế độ riêng tư */ }
    },
    clear: () => {
      try { sessionStorage.removeItem(SID_KEY); } catch { /* bỏ qua */ }
    },
  };
}

export const keySession = createKeySession({ store: idbSessionStore(), sid: sessionStorageSid() });
