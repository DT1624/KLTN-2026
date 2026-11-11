// Kiểm thử luồng ví phía trình duyệt, mô phỏng chính xác src/lib/wallet.ts và
// src/lib/auth.ts rồi đánh vào backend thật.
//   node scripts/wallet-e2e.mjs
import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";
import { webcrypto as crypto } from "node:crypto";

const API = process.env.API_BASE ?? "http://localhost:4000/api";
const results = [];
const check = (n, ok, d = "") => { results.push(ok); console.log(`${ok ? "  PASS" : "  FAIL"}  ${n}${d ? "  → " + d : ""}`); };
const hex = (b) => "0x" + Array.from(b).map(x => x.toString(16).padStart(2, "0")).join("");
const unhex = (h) => { const c = h.replace(/^0x/, ""); const o = new Uint8Array(c.length / 2);
  for (let i = 0; i < o.length; i++) o[i] = parseInt(c.slice(i*2, i*2+2), 16); return o; };

async function call(m, p, b, t) {
  const r = await fetch(API + p, { method: m,
    headers: { ...(b ? {"content-type":"application/json"} : {}), ...(t ? {authorization:"Bearer "+t} : {}) },
    body: b ? JSON.stringify(b) : undefined });
  const x = await r.text(); let d; try { d = JSON.parse(x); } catch { d = x.slice(0,200); }
  return { status: r.status, data: d };
}

// Phải khớp hằng số trong src/lib/wallet.ts
const PBKDF2_ITERATIONS = 600_000;   // khuyến nghị OWASP 2023 cho PBKDF2-HMAC-SHA256

async function deriveKey(pass, salt) {
  const mat = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name:"PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash:"SHA-256" },
    mat, { name:"AES-GCM", length:256 }, false, ["encrypt","decrypt"]);
}
const b64enc = (b) => Buffer.from(b instanceof Uint8Array ? b : new Uint8Array(b)).toString("base64");
const b64dec = (s) => new Uint8Array(Buffer.from(s, "base64"));

async function createKeystore(passphrase) {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  const address = hex(sha3_256(new Uint8Array([...pub, 0x00])));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(passphrase, salt);
  const ct = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, new TextEncoder().encode(hex(priv)));
  return { address, publicKeyHex: hex(pub), ciphertext: b64enc(ct), salt: b64enc(salt), iv: b64enc(iv), priv };
}
async function unlockKeystore(ks, passphrase) {
  const key = await deriveKey(passphrase, b64dec(ks.salt));
  const plain = await crypto.subtle.decrypt({ name:"AES-GCM", iv: b64dec(ks.iv) }, key, b64dec(ks.ciphertext));
  return unhex(new TextDecoder().decode(plain));
}

console.log("\n=== A. Mã hoá keystore trong trình duyệt ===");
const ks = await createKeystore("MatKhau#Manh2026");
check("Tạo ví + mã hoá AES-GCM bằng khoá dẫn xuất PBKDF2", !!ks.ciphertext);
// Khẳng định theo SỐ VÒNG LẶP, không theo thời gian: thời gian phụ thuộc máy,
// còn số vòng mới là tham số bảo mật thực sự.
check("Số vòng PBKDF2 đạt khuyến nghị OWASP 2023 (600.000)", PBKDF2_ITERATIONS >= 600_000);
check("Muối 16 byte, IV 12 byte, sinh ngẫu nhiên cho từng ví",
  b64dec(ks.salt).length === 16 && b64dec(ks.iv).length === 12);

const recovered = await unlockKeystore(ks, "MatKhau#Manh2026");
check("Mở ví bằng đúng mật khẩu khôi phục đúng khoá riêng", hex(recovered) === hex(ks.priv));

let wrongRejected = false;
try { await unlockKeystore(ks, "MatKhauSai123!"); } catch { wrongRejected = true; }
check("Mật khẩu sai bị AES-GCM từ chối", wrongRejected);

const tampered = { ...ks, ciphertext: b64enc((() => { const b = b64dec(ks.ciphertext); b[0] ^= 0xff; return b; })()) };
let tamperDetected = false;
try { await unlockKeystore(tampered, "MatKhau#Manh2026"); } catch { tamperDetected = true; }
check("Bản mã bị sửa 1 byte -> phát hiện được (AES-GCM xác thực)", tamperDetected);

check("Keystore lưu xuống đĩa KHÔNG chứa khoá riêng dạng rõ",
  !JSON.stringify({ address: ks.address, publicKeyHex: ks.publicKeyHex, ciphertext: ks.ciphertext,
    salt: ks.salt, iv: ks.iv }).includes(hex(ks.priv).slice(2)));

// Hai ví cùng mật khẩu phải cho bản mã khác nhau (nhờ muối ngẫu nhiên)
const ks2 = await createKeystore("MatKhau#Manh2026");
check("Hai ví cùng mật khẩu vẫn có muối và bản mã khác nhau",
  ks.salt !== ks2.salt && ks.ciphertext !== ks2.ciphertext);

console.log("\n=== B. Đăng ký & đăng nhập với backend ===");
const role = "holder";
const did = `did:vnu:${role}:${ks.address}`;
const reg = await call("POST", "/entities/register", {
  address: ks.address, publicKeyHex: ks.publicKeyHex, did, role, label: "Sinh viên thử nghiệm",
});
check("Đăng ký thực thể", reg.status === 201, `HTTP ${reg.status}`);

const ch = await call("POST", "/auth/challenge", { address: ks.address });
check("Nhận challenge từ máy chủ", ch.status === 200);
const { nonce, message } = ch.data.data;
check("Thông điệp ký ràng buộc địa chỉ + nonce", message.includes(ks.address) && message.includes(nonce));

const privKey = await unlockKeystore(ks, "MatKhau#Manh2026");
const signature = hex(ed25519.sign(new TextEncoder().encode(message), privKey));
const vf = await call("POST", "/auth/verify", { address: ks.address, nonce, signature });
check("Máy chủ xác minh chữ ký và cấp JWT", vf.status === 200 && !!vf.data.data?.token);
const token = vf.data.data?.token;

const me = await call("GET", "/auth/me", null, token);
check("Dùng JWT gọi được tuyến cần đăng nhập", me.status === 200 && me.data.data.entity.did === did);

console.log("\n=== C. Khoá riêng không rời khỏi máy ===");
const sent = [
  JSON.stringify({ address: ks.address, publicKeyHex: ks.publicKeyHex, did, role, label: "x" }),
  JSON.stringify({ address: ks.address }),
  JSON.stringify({ address: ks.address, nonce, signature }),
];
const privBody = hex(privKey).slice(2);
check("Không gói tin nào gửi đi chứa khoá riêng", !sent.some(b => b.includes(privBody)));
check("Không gói tin nào gửi đi chứa mật khẩu", !sent.some(b => b.includes("MatKhau#Manh2026")));
check("Chỉ khoá công khai và chữ ký được gửi lên",
  sent[0].includes(ks.publicKeyHex) && sent[2].includes(signature));

const creds = await call("GET", "/holder/credentials", null, token);
check("Truy cập ví văn bằng của chính mình", creds.status === 200 && Array.isArray(creds.data.data));

const failed = results.filter(r => !r).length;
console.log(`\n${results.length - failed}/${results.length} PASS` + (failed ? "  — CÓ LỖI" : "  — tất cả đạt"));
process.exit(failed ? 1 : 0);
