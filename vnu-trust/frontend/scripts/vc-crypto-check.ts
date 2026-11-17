// Kiểm lớp mã hoá văn bằng (src/lib/vcCrypto.ts) — chạy CHÍNH mã giao diện dùng.
//
//   ../backend/node_modules/.bin/tsx scripts/vc-crypto-check.ts
//
// Yêu cầu P3 phải chứng minh: có CID (bản mã) mà không có khoá thì KHÔNG đọc được;
// holder đọc được; người xác minh qua liên kết đọc được; sửa bản mã thì phát hiện.
// Phần "bước 7 vẫn bắt được nội dung bị sửa" nằm ở backend/scripts/tamper-check.mjs.
import { ed25519, x25519, edwardsToMontgomeryPriv, edwardsToMontgomeryPub } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";
import {
  encryptCredential, decryptCredential, checkCredential, encryptShare, decryptShare, envelopeAad,
  type VcEnvelope,
} from "../src/lib/vcCrypto";
import { sha3_256Hex, canonicalize } from "../src/lib/wallet";

const rows: { name: string; ok: boolean }[] = [];
const check = (name: string, ok: boolean, detail = "") => {
  rows.push({ name, ok });
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  → " + detail : ""}`);
};
const hex = (b: Uint8Array) => "0x" + Buffer.from(b).toString("hex");
const wallet = () => {
  const privateKey = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKeyHex: hex(pub), address: hex(sha3_256(new Uint8Array([...pub, 0]))) };
};
// Dac ta doi 17/11: vcIdHash = SHA3-256 THO cua vcId (byte UTF-8), khop backend TS/Go
// (vc.service.ts:73, credential.go:214). Ham cu sha3_256Hex(vcId) bam chuoi JSON co dau nhay
// nen may chu bao 400 "Hash cua vcId khong khop". Dung ham giao dien that neu da co,
// con khong thi dung ham tho cuc bo de cac phep ben duoi van kiem dung dieu cu (AAD).
const rawVcIdHash = (v: string) => "0x" + Buffer.from(sha3_256(new TextEncoder().encode(v))).toString("hex");
let uiVcIdHash: ((v: string) => string) | null = null;
let uiVcIdMissing = "";
try { uiVcIdHash = (await import("../src/lib/vcid")).vcIdHash; } catch (e) { uiVcIdMissing = String(e); }
const vcIdHashOf = uiVcIdHash ?? rawVcIdHash;
const throws = async (f: () => Promise<unknown>) => { try { await f(); return false; } catch { return true; } };

console.log("\n=== Quy ước băm vcId khớp máy chủ ===");
{
  const { createHash } = await import("node:crypto");
  const vectors: [string, string][] = [
    ["urn:uuid:00000000-0000-4000-8000-000000000000", "0xf618bc0a0c3e9391cd60c27430da73a3cd434ff1cce8685ff4dca1a3907519f3"],
    ["x", "0x741efa311f97686956946758e0d95f70f11ff2da4f2feb7c54314f44134ac49f"],
  ];
  for (const [v, want] of vectors) {
    check(`Vector độc lập (@noble = node:crypto như backend TS) cho "${v.slice(0, 20)}"`,
      rawVcIdHash(v) === want && "0x" + createHash("sha3-256").update(v).digest("hex") === want);
    check(`Hàm cũ sha3_256Hex("${v.slice(0, 20)}") KHÁC vector (băm chuỗi JSON có nháy → máy chủ 400)`, sha3_256Hex(v) !== want);
    check(`Hàm giao diện thật vcIdHash("${v.slice(0, 20)}") = vector`,
      uiVcIdHash !== null && uiVcIdHash(v) === want,
      uiVcIdHash ? "" : "chưa có src/lib/vcid.ts — giao diện vẫn băm vcId bằng sha3_256Hex (có nháy)");
  }
}

console.log("\n=== Dẫn khoá X25519 từ khoá Ed25519 của ví ===");
let same = true;
for (let i = 0; i < 5; i++) {
  const w = wallet();
  same &&= hex(x25519.getPublicKey(edwardsToMontgomeryPriv(w.privateKey))) === hex(edwardsToMontgomeryPub(w.publicKeyHex.slice(2)));
}
check("Khoá công khai X25519 dẫn từ khoá riêng = dẫn từ khoá công khai (5 ví ngẫu nhiên)", same);

console.log("\n=== Phong bì văn bằng ===");
const issuer = wallet(), holder = wallet(), stranger = wallet();
const vcId = `urn:uuid:${crypto.randomUUID()}`;
const vcIdHash = vcIdHashOf(vcId);
const vc = {
  "@context": ["https://www.w3.org/2018/credentials/v1"], id: vcId, type: ["VerifiableCredential"],
  issuer: `did:vnu:issuer:${issuer.address}`, issuanceDate: new Date().toISOString(),
  credentialSubject: { id: `did:vnu:holder:${holder.address}`, "vnu:studentId": "22028334", "vnu:degreeName": "Cử nhân Công nghệ thông tin", "vnu:gpa": "3.42" },
};
const contentHash = sha3_256Hex(vc);
const env = await encryptCredential(vc, vcIdHash, [
  { address: holder.address, role: "holder", ed25519PubHex: holder.publicKeyHex },
  { address: issuer.address, role: "issuer", ed25519PubHex: issuer.publicKeyHex },
]);
const raw = JSON.stringify(env);
check("Phong bì (thứ nằm trên IPFS) KHÔNG chứa bản rõ: mã SV, tên văn bằng, điểm, DID",
  !raw.includes("22028334") && !raw.includes("Công nghệ") && !raw.includes("3.42") && !raw.includes("did:vnu"));
check("Phong bì chỉ có các trường đã đặc tả", Object.keys(env).sort().join(",") === "aad,alg,ct,iv,recipients,v"
  && env.recipients.every((r) => Object.keys(r).sort().join(",") === "epk,iv,kid,role,wk"));
check("aad gắn phong bì với đúng văn bằng", env.aad === envelopeAad(vcIdHash));

const byHolder = await decryptCredential(env, holder);
check("Holder giải mã được, đúng từng trường", canonicalize(byHolder) === canonicalize(vc));
check("Hash bản rõ sau giải mã = content_hash neo trên chuỗi (bước 7 giữ nguyên)", sha3_256Hex(byHolder) === contentHash);
check("Issuer giải mã được (để cấp lại / đối soát)", sha3_256Hex(await decryptCredential(env, issuer)) === contentHash);
check("Người KHÔNG phải người nhận (có CID, không có khoá) → không đọc được", await throws(() => decryptCredential(env, stranger)));
// Kẻ có bản mã giả làm người nhận bằng cách sửa kid thành địa chỉ của mình: khoá bọc
// được dẫn theo kid nên không mở được.
const forged: VcEnvelope = { ...env, recipients: env.recipients.map((r) => (r.role === "holder" ? { ...r, kid: stranger.address } : r)) };
check("Sửa kid thành địa chỉ của mình → vẫn không đọc được", await throws(() => decryptCredential(forged, stranger)));

const flip = (b64s: string) => { const b = Buffer.from(b64s, "base64"); b[b.length - 1] ^= 1; return b.toString("base64"); };
check("Sửa 1 bit bản mã → GCM phát hiện", await throws(() => decryptCredential({ ...env, ct: flip(env.ct) }, holder)));
check("Sửa khoá bọc của holder → phát hiện", await throws(() => decryptCredential(
  { ...env, recipients: env.recipients.map((r) => (r.role === "holder" ? { ...r, wk: flip(r.wk) } : r)) }, holder)));
check("Đổi aad (ghép phong bì sang văn bằng khác) → phát hiện", await throws(() => decryptCredential({ ...env, aad: envelopeAad(vcIdHashOf("urn:uuid:khac")) }, holder)));

console.log("\n=== Ví holder tự kiểm sau khi giải mã (thay phép kiểm hash máy chủ không còn làm được) ===");
const exp = { vcId, contentHash, holderDid: `did:vnu:holder:${holder.address}`, vcIdHash };
check("Văn bằng đúng → không có vấn đề nào", checkCredential(byHolder, exp, env).length === 0);
const bad = { ...byHolder, credentialSubject: { ...(byHolder.credentialSubject as object), "vnu:gpa": "4.00" } };
check("Issuer neo hash A nhưng gửi nội dung B → ví báo lệch hash", checkCredential(bad, exp).some((p) => p.includes("Hash")));
check("Văn bằng cấp cho DID khác → ví báo", checkCredential(byHolder, { ...exp, holderDid: "did:vnu:holder:0x1" }).length > 0);

console.log("\n=== Liên kết chia sẻ (#k=…) ===");
const vp = { type: ["VerifiablePresentation"], holder: exp.holderDid, verifiableCredential: [byHolder] };
const { blob, key } = await encryptShare(vp);
check("Bản trình bày đã mã hoá không chứa bản rõ", !JSON.stringify(blob).includes("22028334") && !JSON.stringify(blob).includes("did:vnu"));
check("Khoá trong fragment là base64url 43 ký tự (256 bit)", /^[A-Za-z0-9_-]{43}$/.test(key));
check("Người xác minh có liên kết đầy đủ → mở được", sha3_256Hex(await decryptShare(blob, key)) === sha3_256Hex(vp));
check("Chỉ có bản mã (máy chủ, không có fragment) → không mở được", await throws(() => decryptShare(blob, Buffer.from(new Uint8Array(32)).toString("base64url"))));
check("Sửa bản mã của bản trình bày → phát hiện", await throws(() => decryptShare({ ...blob, ct: flip(blob.ct) }, key)));

console.log("\n=== Hiệu năng (Node, WebCrypto + @noble — không chạy PBKDF2) ===");
const N = 200;
const times: number[] = [];
for (let i = 0; i < N; i++) {
  const t0 = performance.now();
  const e = await encryptCredential(vc, vcIdHash, [
    { address: holder.address, role: "holder", ed25519PubHex: holder.publicKeyHex },
    { address: issuer.address, role: "issuer", ed25519PubHex: issuer.publicKeyHex },
  ]);
  await decryptCredential(e, holder);
  times.push(performance.now() - t0);
}
times.sort((a, b) => a - b);
const p50 = times[Math.floor(N * 0.5)], p95 = times[Math.floor(N * 0.95)];
check(`Mã hoá (2 người nhận) + giải mã một văn bằng: p50 ${p50.toFixed(2)} ms, p95 ${p95.toFixed(2)} ms (< 50 ms)`, p95 < 50);

const failed = rows.filter((r) => !r.ok);
console.log(`\n${rows.length - failed.length}/${rows.length} PASS  — ${failed.length ? failed.length + " FAIL" : "mã hoá văn bằng đúng đặc tả"}`);
process.exit(failed.length ? 1 : 0);
