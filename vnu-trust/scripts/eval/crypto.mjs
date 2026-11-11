/**
 * Thí nghiệm A — chi phí các phép mật mã mà ví chạy phía máy khách.
 *
 * Đo đúng thư viện giao diện dùng (@noble/curves, @noble/hashes, @scure/bip39,
 * WebCrypto cho PBKDF2/AES-GCM), mỗi phép lặp REPEATS lượt rồi báo trung vị và
 * hệ số biến thiên. Đây là các phép thuần CPU nên nhiễu thấp hơn nhiều so với
 * phép đo qua HTTP — dùng làm mốc để đọc các thí nghiệm còn lại.
 *
 *   node scripts/eval/crypto.mjs        (chạy từ frontend/, xem eval.sh)
 */
import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";
import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha512";
import { generateMnemonic, mnemonicToSeedSync } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { createHash, webcrypto, randomBytes } from "node:crypto";
import { writeFileSync, mkdirSync } from "node:fs";
import os from "node:os";

const OUT = process.env.OUT_DIR ?? "./.bench/eval";
const REPEATS = Number(process.env.REPEATS ?? 7);
const subtle = webcrypto.subtle;

const median = (a) => { const s = [...a].sort((x, y) => x - y); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const mean = (a) => a.reduce((x, y) => x + y, 0) / a.length;
const cv = (a) => { const m = mean(a); return Math.sqrt(a.reduce((s, x) => s + (x - m) ** 2, 0) / (a.length - 1)) / m * 100; };
const summary = (a) => ({ median: median(a), min: Math.min(...a), max: Math.max(...a), cv: cv(a), n: a.length });

/** Thời gian (ms) cho `iters` lần gọi fn, lặp REPEATS lượt sau một lượt khởi động. */
async function timeIt(fn, iters, repeats = REPEATS) {
  for (let i = 0; i < Math.min(iters, 50); i++) await fn();
  const runs = [];
  for (let r = 0; r < repeats; r++) {
    const t0 = performance.now();
    for (let i = 0; i < iters; i++) await fn();
    runs.push(performance.now() - t0);
  }
  return runs;
}

const out = { meta: { at: new Date().toISOString(), node: process.version, cpu: os.cpus()[0].model, cores: os.cpus().length, repeats: REPEATS }, data: {} };
const log = (...x) => console.log("  ", ...x);

// ---------------------------------------------------------------- Ed25519
{
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  // Đúng khuôn thông điệp đăng nhập — kích thước điển hình của một phép ký.
  const msg = new TextEncoder().encode(`VNU-Trust xac thuc dang nhap\ndia chi: 0x${"ab".repeat(32)}\nnonce: ${"cd".repeat(16)}`);
  const sig = ed25519.sign(msg, priv);
  const N = 500;
  const ops = {
    keygen: await timeIt(() => ed25519.getPublicKey(ed25519.utils.randomPrivateKey()), N),
    sign: await timeIt(() => ed25519.sign(msg, priv), N),
    verify: await timeIt(() => ed25519.verify(sig, msg, pub), N),
  };
  out.data.ed25519 = Object.fromEntries(Object.entries(ops).map(([k, runs]) => {
    const perOp = runs.map((t) => (t / N) * 1000); // µs/phép
    return [k, { us: summary(perOp), opsPerSec: 1e6 / median(perOp) }];
  }));
  for (const [k, v] of Object.entries(out.data.ed25519)) log(`ed25519.${k}: ${v.us.median.toFixed(1)} µs (CV ${v.us.cv.toFixed(1)}%)`);
}

// ---------------------------------------------------------------- SHA3-256 theo kích thước
{
  const sizes = [64, 256, 1024, 4096, 16384, 65536, 262144, 1048576];
  out.data.sha3 = [];
  for (const size of sizes) {
    const buf = randomBytes(size);
    const iters = Math.max(20, Math.floor(4_000_000 / size));
    const noble = await timeIt(() => sha3_256(buf), iters);
    const native = await timeIt(() => createHash("sha3-256").update(buf).digest(), iters);
    const mbps = (runs) => runs.map((t) => (size * iters) / (t / 1000) / 1e6);
    const row = { size, noble: summary(mbps(noble)), native: summary(mbps(native)) };
    out.data.sha3.push(row);
    log(`sha3 ${size} B: noble ${row.noble.median.toFixed(1)} MB/s, native ${row.native.median.toFixed(1)} MB/s`);
  }
}

// ---------------------------------------------------------------- Chuẩn hoá + băm một văn bằng thật
{
  const canon = (v) => v === null || typeof v !== "object" ? JSON.stringify(v)
    : Array.isArray(v) ? "[" + v.map(canon).join(",") + "]"
    : "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
  const holder = `did:vnu:holder:0x${"7f".repeat(32)}`;
  const vc = {
    "@context": ["https://www.w3.org/2018/credentials/v1", { vnu: "https://vnu.edu.vn/credentials/v1#" }],
    id: "urn:uuid:3f1c8a5e-2b7d-4e0a-9c61-5d2f8b9e7a10", type: ["VerifiableCredential", "VNUDegreeCredential"],
    issuer: `did:vnu:issuer:0x${"1a".repeat(32)}`, issuanceDate: "2026-06-30T08:15:42.317Z",
    credentialSubject: { id: holder, "vnu:studentId": "22028334", "vnu:degreeName": "Cử nhân Công nghệ thông tin",
      "vnu:faculty": "Trường Đại học Công nghệ", "vnu:gpa": "3.42", "vnu:graduationYear": "2026" },
  };
  const bytes = new TextEncoder().encode(canon(vc)).length;
  const N = 2000;
  const canonOnly = await timeIt(() => canon(vc), N);
  const full = await timeIt(() => sha3_256(new TextEncoder().encode(canon(vc))), N);
  const us = (runs) => runs.map((t) => (t / N) * 1000);
  out.data.vcHash = { bytes, canonUs: summary(us(canonOnly)), canonHashUs: summary(us(full)) };
  log(`VC ${bytes} B: chuẩn hoá ${median(us(canonOnly)).toFixed(1)} µs, chuẩn hoá+băm ${median(us(full)).toFixed(1)} µs`);
}

// ---------------------------------------------------------------- PBKDF2-SHA256 theo số vòng (WebCrypto, đúng đường của ví)
{
  const pw = new TextEncoder().encode("mat-khau-thu-nghiem-123");
  const salt = randomBytes(16);
  const material = await subtle.importKey("raw", pw, "PBKDF2", false, ["deriveBits"]);
  const derive = (iterations) => subtle.deriveBits({ name: "PBKDF2", salt, iterations, hash: "SHA-256" }, material, 256);
  const levels = [10_000, 50_000, 100_000, 210_000, 310_000, 600_000, 1_000_000, 2_000_000];
  out.data.pbkdf2 = [];
  await derive(10_000);
  for (const it of levels) {
    const runs = [];
    for (let r = 0; r < REPEATS; r++) { const t0 = performance.now(); await derive(it); runs.push(performance.now() - t0); }
    out.data.pbkdf2.push({ iterations: it, ms: summary(runs) });
    log(`pbkdf2 ${it}: ${median(runs).toFixed(1)} ms`);
  }
  // AES-256-GCM trên khoá riêng 32 byte: để thấy phần đắt nằm ở dẫn xuất khoá chứ không ở mã hoá.
  const key = await subtle.importKey("raw", randomBytes(32), "AES-GCM", false, ["encrypt", "decrypt"]);
  const iv = randomBytes(12);
  const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, randomBytes(32)));
  const N = 2000;
  const enc = await timeIt(() => subtle.encrypt({ name: "AES-GCM", iv }, key, randomBytes(32)), N);
  const dec = await timeIt(() => subtle.decrypt({ name: "AES-GCM", iv }, key, ct), N);
  out.data.aesgcm = { encryptUs: summary(enc.map((t) => (t / N) * 1000)), decryptUs: summary(dec.map((t) => (t / N) * 1000)) };
  log(`aes-gcm: ${out.data.aesgcm.encryptUs.median.toFixed(1)} µs mã hoá`);
}

// ---------------------------------------------------------------- BIP-39 + SLIP-0010 (khôi phục trên máy khác)
{
  const HARD = 0x80000000;
  const derive = (seed) => {
    let I = hmac(sha512, new TextEncoder().encode("ed25519 seed"), seed);
    let key = I.slice(0, 32), cc = I.slice(32);
    for (const idx of [44, 637, 0, 0, 0]) {
      const d = new Uint8Array(37); d.set(key, 1); new DataView(d.buffer).setUint32(33, (idx + HARD) >>> 0, false);
      I = hmac(sha512, cc, d); key = I.slice(0, 32); cc = I.slice(32);
    }
    return key;
  };
  const phrase = generateMnemonic(wordlist, 128);
  const seedRuns = await timeIt(() => mnemonicToSeedSync(phrase), 3);
  const seed = mnemonicToSeedSync(phrase);
  const pathRuns = await timeIt(() => derive(seed), 500);
  out.data.bip39 = { seedMs: summary(seedRuns.map((t) => t / 3)), slip10Us: summary(pathRuns.map((t) => (t / 500) * 1000)) };
  log(`bip39 seed: ${out.data.bip39.seedMs.median.toFixed(1)} ms, slip10: ${out.data.bip39.slip10Us.median.toFixed(1)} µs`);
}

mkdirSync(OUT, { recursive: true });
writeFileSync(`${OUT}/crypto.json`, JSON.stringify(out, null, 2));
console.log(`  → ${OUT}/crypto.json`);
