// Kiểm thử ĐĂNG NHẬP TRÊN THIẾT BỊ KHÁC.
//
// Mô phỏng hai trình duyệt hoàn toàn tách biệt (hai "IndexedDB" riêng, không
// chia sẻ gì) và chứng minh: chỉ với 12 từ, máy B đăng nhập được đúng tài khoản
// đã tạo ở máy A — mà máy chủ KHÔNG hề lưu khoá riêng hay mật khẩu nào.
//
//   node scripts/cross-device.mjs
import { generateMnemonic, mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha512";
import { sha3_256 } from "@noble/hashes/sha3";
import { ed25519 } from "@noble/curves/ed25519";
import { webcrypto as crypto } from "node:crypto";

const API = process.env.API_BASE ?? "http://localhost:4000/api";
const results = [];
const check = (n, ok, d = "") => { results.push(ok); console.log(`${ok ? "  PASS" : "  FAIL"}  ${n}${d ? "  → " + d : ""}`); };
const hex = (b) => "0x" + Array.from(b).map(x => x.toString(16).padStart(2, "0")).join("");
const unhex = (h) => { const c = h.replace(/^0x/, ""); const o = new Uint8Array(c.length/2);
  for (let i=0;i<o.length;i++) o[i]=parseInt(c.slice(i*2,i*2+2),16); return o; };

async function call(m, p, b, t) {
  const r = await fetch(API + p, { method: m,
    headers: { ...(b ? {"content-type":"application/json"} : {}), ...(t ? {authorization:"Bearer "+t} : {}) },
    body: b ? JSON.stringify(b) : undefined });
  const x = await r.text(); let d; try { d = JSON.parse(x); } catch { d = x.slice(0,200); }
  return { status: r.status, data: d };
}

// ---- Bản sao chính xác src/lib/mnemonic.ts ----
const HARDENED = 0x80000000;
const master = (seed) => { const I = hmac(sha512, new TextEncoder().encode("ed25519 seed"), seed);
  return { key: I.slice(0,32), chainCode: I.slice(32) }; };
const child = (p, i) => { const d = new Uint8Array(37); d[0]=0; d.set(p.key,1);
  new DataView(d.buffer).setUint32(33, i>>>0, false);
  const I = hmac(sha512, p.chainCode, d); return { key: I.slice(0,32), chainCode: I.slice(32) }; };
function privFromMnemonic(phrase, path = "m/44'/637'/0'/0'/0'") {
  const norm = phrase.trim().toLowerCase().split(/\s+/).join(" ");
  if (!validateMnemonic(norm, wordlist)) throw new Error("cụm từ không hợp lệ");
  let node = master(mnemonicToSeedSync(norm));
  for (const seg of path.split("/").slice(1)) {
    const h = seg.endsWith("'");
    node = child(node, parseInt(h ? seg.slice(0,-1) : seg, 10) + (h ? HARDENED : 0));
  }
  return node.key;
}
const addressOf = (pub) => hex(sha3_256(new Uint8Array([...pub, 0x00])));

// ---- Bản sao lớp mã hoá keystore, mỗi "máy" một kho riêng ----
const PBKDF2_ITERATIONS = 600_000;
async function deriveKey(pass, salt) {
  const mat = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name:"PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash:"SHA-256" },
    mat, { name:"AES-GCM", length:256 }, false, ["encrypt","decrypt"]);
}
const b64e = (b) => Buffer.from(b instanceof Uint8Array ? b : new Uint8Array(b)).toString("base64");
const b64d = (s) => new Uint8Array(Buffer.from(s, "base64"));

/** Một "trình duyệt": có kho IndexedDB riêng, không chia sẻ gì với máy khác. */
function newDevice(name) {
  const indexedDB = new Map();
  return {
    name,
    async saveWallet(priv, passphrase, meta) {
      const pub = ed25519.getPublicKey(priv);
      const address = addressOf(pub);
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const key = await deriveKey(passphrase, salt);
      const ct = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, new TextEncoder().encode(hex(priv)));
      indexedDB.set(address, { address, publicKeyHex: hex(pub), ciphertext: b64e(ct),
        salt: b64e(salt), iv: b64e(iv), ...meta });
      return { address, publicKeyHex: hex(pub) };
    },
    async unlock(address, passphrase) {
      const rec = indexedDB.get(address);
      if (!rec) throw new Error(`${name}: không có ví này trên máy`);
      const key = await deriveKey(passphrase, b64d(rec.salt));
      const plain = await crypto.subtle.decrypt({ name:"AES-GCM", iv: b64d(rec.iv) }, key, b64d(rec.ciphertext));
      return unhex(new TextDecoder().decode(plain));
    },
    has: (address) => indexedDB.has(address),
    size: () => indexedDB.size,
    dump: () => JSON.stringify([...indexedDB.values()]),
  };
}

async function login(address, priv) {
  const ch = await call("POST", "/auth/challenge", { address });
  if (ch.status !== 200) return { ok: false, status: ch.status, error: ch.data?.error };
  const sig = hex(ed25519.sign(new TextEncoder().encode(ch.data.data.message), priv));
  const vf = await call("POST", "/auth/verify", { address, nonce: ch.data.data.nonce, signature: sig });
  return { ok: vf.status === 200, status: vf.status, token: vf.data?.data?.token, entity: vf.data?.data?.entity };
}

// ============ KỊCH BẢN ============

console.log("\n=== MÁY A: tạo ví mới ===");
const deviceA = newDevice("Máy A");
const mnemonic = generateMnemonic(wordlist, 128);
check("Sinh cụm từ 12 từ hợp lệ", mnemonic.split(" ").length === 12 && validateMnemonic(mnemonic, wordlist));

const privA = privFromMnemonic(mnemonic);
const pubA = ed25519.getPublicKey(privA);
const address = addressOf(pubA);
const role = "holder";
const did = `did:vnu:${role}:${address}`;

await deviceA.saveWallet(privA, "MatKhauMayA#2026", { did, role, label: "Nguyễn Văn A" });
const reg = await call("POST", "/entities/register", { address, publicKeyHex: hex(pubA), did, role, label: "Nguyễn Văn A" });
check("Ghi danh hồ sơ công khai lên máy chủ", reg.status === 201);

const loginA = await login(address, await deviceA.unlock(address, "MatKhauMayA#2026"));
check("Máy A đăng nhập được", loginA.ok, `vai trò ${loginA.entity?.role}`);

console.log("\n=== MÁY B: thiết bị hoàn toàn mới, chỉ có 12 từ ===");
const deviceB = newDevice("Máy B");
check("Máy B khởi đầu trống rỗng", deviceB.size() === 0 && !deviceB.has(address));

// Người dùng gõ lại 12 từ (có sai hoa/thường và thừa khoảng trắng như thực tế)
const typed = "  " + mnemonic.toUpperCase().split(" ").join("   ") + "  ";
const privB = privFromMnemonic(typed);
check("Chuẩn hoá được cụm từ gõ tay (hoa/thường, khoảng trắng thừa)", hex(privB) === hex(privA));

const pubB = ed25519.getPublicKey(privB);
check("Sinh lại ĐÚNG địa chỉ ví cũ", addressOf(pubB) === address, address.slice(0, 20) + "…");

// Máy B tra máy chủ để lấy vai trò cũ. Tên hiển thị KHÔNG còn trên tuyến công
// khai (P-05, docs/SECURITY_REVIEW.md) — giao diện đặt "Ví khôi phục" như dưới đây.
const lookup = await call("GET", `/entities/by-address/${address}`);
check("Tra được hồ sơ công khai từ máy chủ", lookup.status === 200 && lookup.data.data.did === did,
  `${lookup.data?.data?.role}`);
check("Hồ sơ công khai không lộ tên hiển thị", lookup.data?.data?.label === null);

// Đặt mật khẩu KHÁC ở máy B — mật khẩu là cục bộ từng máy
await deviceB.saveWallet(privB, "MatKhauMayB@KhacHan99", { did, role, label: lookup.data.data.label ?? "Ví khôi phục" });
const loginB = await login(address, await deviceB.unlock(address, "MatKhauMayB@KhacHan99"));
check("Máy B đăng nhập ĐÚNG tài khoản đó", loginB.ok && loginB.entity?.did === did);
check("Mật khẩu hai máy khác nhau vẫn cùng một tài khoản", loginB.entity?.address === loginA.entity?.address);

console.log("\n=== Bảo đảm an toàn ===");
check("Máy chủ KHÔNG lưu khoá riêng (hồ sơ chỉ có khoá công khai)",
  !JSON.stringify(lookup.data).includes(hex(privA).slice(2)));
check("Máy chủ KHÔNG lưu mật khẩu",
  !JSON.stringify(lookup.data).includes("MatKhauMayA") && !JSON.stringify(lookup.data).includes("MatKhauMayB"));
check("Máy chủ KHÔNG lưu cụm từ ghi nhớ", !JSON.stringify(lookup.data).includes(mnemonic.split(" ")[0] + " "));
check("Kho trên máy B không chứa khoá riêng dạng rõ", !deviceB.dump().includes(hex(privA).slice(2)));
check("Mật khẩu máy A không mở được ví ở máy B",
  await deviceB.unlock(address, "MatKhauMayA#2026").then(() => false).catch(() => true));

// Cụm từ sai một từ -> ra ví khác hẳn, không chiếm được tài khoản
const words = mnemonic.split(" ");
const wrong = [...words]; wrong[0] = words[0] === "abandon" ? "ability" : "abandon";
let wrongAddr = null;
try { wrongAddr = addressOf(ed25519.getPublicKey(privFromMnemonic(wrong.join(" ")))); } catch { /* mã kiểm tra bắt được */ }
check("Sai một từ thì KHÔNG ra được ví cũ", wrongAddr !== address,
  wrongAddr ? "ra ví khác" : "bị mã kiểm tra BIP39 chặn");

// Không có cụm từ thì không đăng nhập được
const intruderPriv = ed25519.utils.randomPrivateKey();
const intruderTry = await login(address, intruderPriv);
check("Biết địa chỉ nhưng không có khoá thì không đăng nhập được", !intruderTry.ok, `HTTP ${intruderTry.status}`);

console.log("\n=== Máy A vẫn hoạt động bình thường sau đó ===");
const loginA2 = await login(address, await deviceA.unlock(address, "MatKhauMayA#2026"));
check("Máy A đăng nhập lại được (hai máy dùng song song)", loginA2.ok);

const failed = results.filter(r => !r).length;
console.log(`\n${results.length - failed}/${results.length} PASS` + (failed ? "  — CÓ LỖI" : "  — tất cả đạt"));
process.exit(failed ? 1 : 0);
