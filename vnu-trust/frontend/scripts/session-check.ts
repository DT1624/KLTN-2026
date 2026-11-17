// Kiem thu src/lib/session.ts (giu phien qua F5, phuong an C):
//   ../backend/node_modules/.bin/tsx scripts/session-check.ts
//
// Ghi chu: test nay chay LO-GIC (store/sid gia bang Map, WebCrypto cua Node).
// Hanh vi F5 that trong trinh duyet se kiem bang Playwright o buoc xac nhan.
//
// Thiet ke: khoa rieng Ed25519 duoc boc bang CryptoKey AES-GCM extractable:false
// (AAD = dia chi), ban ghi nam o IndexedDB rieng; sessionStorage chi giu sid.

import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";
import type { UnlockedWallet } from "../src/lib/wallet";

let failed = 0, total = 0;
const check = (name: string, ok: boolean, detail = "") => {
  total++;
  if (!ok) failed++;
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  -> " + detail : ""}`);
};
const finish = () => {
  console.log(`\nPhien vi qua F5: ${total - failed}/${total} dat`);
  process.exit(failed ? 1 : 0);
};

let mod: typeof import("../src/lib/session");
try {
  // SESSION_MODULE=<duong dan> de tro vao ban dot bien (chung minh test chuyen do).
  mod = await import(process.env.SESSION_MODULE ?? "../src/lib/session");
} catch (e) {
  console.log(`  FAIL  chua co src/lib/session.ts  -> ${(e as Error).message.split("\n")[0]}`);
  total = 1; failed = 1;
  finish();
  process.exit(1);
}
const { createKeySession } = mod!;

const hex = (b: Uint8Array) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
function makeWallet(label = "Sinh vien A"): UnlockedWallet {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  const address = "0x" + hex(sha3_256(new Uint8Array([...pub, 0])));
  return {
    address, publicKeyHex: "0x" + hex(pub), did: `did:vnu:${address}`, role: "holder", label,
    keyPair: { privateKey: priv, publicKeyHex: "0x" + hex(pub), address },
  };
}
function makeEnv(startNow = 1_000_000) {
  const recs = new Map<string, any>();
  let sidVal: string | null = null;
  let t = startNow;
  const store = {
    get: async (id: string) => recs.get(id),
    put: async (r: any) => { recs.set(r.sessionId, r); },
    delete: async (id: string) => { recs.delete(id); },
    all: async () => [...recs.values()],
  };
  const sid = { get: () => sidVal, set: (v: string) => { sidVal = v; }, clear: () => { sidVal = null; } };
  const ks = createKeySession({ store, sid, now: () => t });
  return { recs, store, sid, ks, setNow: (n: number) => { t = n; }, setSid: (v: string | null) => { sidVal = v; } };
}
const sameBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);
const throws = async (p: Promise<unknown>) => { try { await p; return false; } catch { return true; } };

// (i) save -> restore trong han
{
  const e = makeEnv(); const w = makeWallet(); const exp = e.setNow && 1_000_000 + 900_000;
  await e.ks.save(w, exp);
  check("save ghi dung mot ban ghi va dat sid 32 hex", e.recs.size === 1 && /^[0-9a-f]{32}$/.test(e.sid.get() ?? ""), String(e.sid.get()));
  e.setNow(1_000_000 + 1000);
  const r = await e.ks.restore();
  check("(i) restore trong han tra ve vi", r !== null);
  check("(i) cung dia chi", r?.wallet.address === w.address);
  check("(i) privateKey khop tung byte", !!r && sameBytes(r.wallet.keyPair.privateKey, w.keyPair.privateKey));
  check("(i) keyPair.address/publicKeyHex giu nguyen", r?.wallet.keyPair.address === w.address && r?.wallet.keyPair.publicKeyHex === w.keyPair.publicKeyHex);
  check("(i) meta (label, role, did) giu nguyen", r?.wallet.label === w.label && r?.wallet.role === w.role && r?.wallet.did === w.did);
  check("(i) expiresAt giu nguyen, khong reset", r?.expiresAt === exp, String(r?.expiresAt));
}

// (ii) qua han
{
  const e = makeEnv(); const w = makeWallet(); const exp = 1_000_000 + 900_000;
  await e.ks.save(w, exp);
  e.setNow(exp + 1);
  const r = await e.ks.restore();
  check("(ii) qua han -> restore null", r === null);
  check("(ii) ban ghi da bi xoa khoi store", e.recs.size === 0, `con ${e.recs.size}`);
}

// (iii) clear
{
  const e = makeEnv(); await e.ks.save(makeWallet(), 2_000_000);
  await e.ks.clear();
  check("(iii) clear -> store rong", e.recs.size === 0);
  check("(iii) clear -> sid da xoa", e.sid.get() === null);
}

// (iv) khong lo khoa ro
{
  const e = makeEnv(); const w = makeWallet(); await e.ks.save(w, 2_000_000);
  const rec = [...e.recs.values()][0];
  const priv = w.keyPair.privateKey, privHex = hex(priv);
  const hasSub = (hay: Uint8Array) => { for (let i = 0; i + priv.length <= hay.length; i++) if (sameBytes(hay.subarray(i, i + priv.length), priv)) return true; return false; };
  let leak = "";
  const scan = (v: unknown, path: string) => {
    if (v instanceof Uint8Array) { if (hasSub(v)) leak = path; }
    else if (typeof v === "string") { if (v.toLowerCase().includes(privHex)) leak = path; }
    else if (Array.isArray(v)) { if (v.length >= 32 && v.every((x) => typeof x === "number") && hasSub(Uint8Array.from(v))) leak = path; v.forEach((x, i) => scan(x, `${path}[${i}]`)); }
    else if (v && typeof v === "object" && !(v as any instanceof CryptoKey)) for (const [k, x] of Object.entries(v)) scan(x, `${path}.${k}`);
  };
  for (const [k, v] of Object.entries(rec)) if (k !== "key") scan(v, k);
  check("(iv) ban ghi khong chua khoa rieng (bytes/hex)", leak === "", leak);
  check("(iv) ban ghi co wrapped + iv + key", rec.wrapped instanceof Uint8Array && rec.iv instanceof Uint8Array && rec.key, "");
  check("(iv) key.extractable === false", rec.key?.extractable === false, String(rec.key?.extractable));
  check("(iv) exportKey('raw') bi tu choi", await throws(globalThis.crypto.subtle.exportKey("raw", rec.key)));
}

// (v) sid khac / rong, purgeOrphans
{
  const e = makeEnv(); const w = makeWallet(); await e.ks.save(w, 2_000_000);
  e.setSid("f".repeat(32));
  check("(v) sid khac (tab khac) -> restore null", (await e.ks.restore()) === null);
  e.setSid(null);
  check("(v) khong co sid -> restore null", (await e.ks.restore()) === null);

  const e2 = makeEnv();
  await e2.ks.save(makeWallet("a"), 5_000_000);
  const keepId = e2.sid.get()!;
  const keep = [...e2.recs.values()][0];
  e2.recs.set("other-sid", { ...keep, sessionId: "other-sid" });            // moi tab khac, con han
  e2.recs.set("stale", { ...keep, sessionId: "stale", expiresAt: 10 });      // qua han
  e2.recs.set(keepId + "x", { ...keep, sessionId: keepId + "x" });           // sid gan giong nhung khac
  await e2.ks.purgeOrphans();
  const ids = [...e2.recs.keys()];
  check("(v) purgeOrphans chi giu ban ghi cua sid hien tai", ids.length === 1 && ids[0] === keepId, JSON.stringify(ids));

  const e3 = makeEnv();
  await e3.ks.save(makeWallet(), 5_000_000);
  e3.setSid(null);
  await e3.ks.purgeOrphans();
  check("(v) khong co sid -> purgeOrphans xoa het ban ghi con lai", e3.recs.size === 0, `con ${e3.recs.size}`);
}

// (vi) trao ban ghi
{
  const e = makeEnv(); const w = makeWallet(); const other = makeWallet("khac");
  await e.ks.save(w, 2_000_000);
  const rec = [...e.recs.values()][0];
  rec.address = other.address;
  let r: unknown = "chua-chay", threw = false;
  try { r = await e.ks.restore(); } catch { threw = true; }
  check("(vi) doi address trong ban ghi -> khong throw ra ngoai", !threw);
  check("(vi) doi address -> restore null (AAD khong khop)", r === null, r === null ? "" : "da tra ve vi");
}

// (vii) touch
{
  const e = makeEnv(); const w = makeWallet(); await e.ks.save(w, 2_000_000);
  await e.ks.touch(3_500_000);
  check("(vii) touch cap nhat expiresAt cua ban ghi", [...e.recs.values()][0]?.expiresAt === 3_500_000);
  e.setNow(3_000_000);
  const r = await e.ks.restore();
  check("(vii) sau touch, restore con han va tra expiresAt moi", r?.expiresAt === 3_500_000, String(r?.expiresAt));
}

finish();
