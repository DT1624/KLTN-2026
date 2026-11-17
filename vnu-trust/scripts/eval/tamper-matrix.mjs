/**
 * M1 — Ma trận phát hiện giả mạo (backend TS, VERIFY_ONCHAIN=false, CSDL cách ly).
 *
 *   node tamper-matrix.mjs        (chạy từ frontend/ để có @noble/*; eval-ts.sh PHASES=tamper lo việc này)
 *
 * Tự dựng 1 issuer, 2 holder (A nạn nhân, B kẻ khác), 8 VC cho A. Mỗi kịch bản gửi
 * POST /verify/share/<token> {vp} và ghi đạt/không đạt của TỪNG bước 1..7 theo đúng
 * thứ tự mảng `checks` của vp.service.ts (1 IPFS, 2 toàn vẹn VP, 3 chữ ký, 4 DID,
 * 5 VC còn hiệu lực, 6 nội dung khớp bản neo, 7 issuer tin cậy - cảnh báo).
 * Không ghi khoá ra đĩa. Ghi $OUT_DIR/tamper.json.
 */
import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";
import { randomUUID, createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { writeFileSync, mkdirSync } from "node:fs";

const TS = process.env.TS_BASE ?? "http://localhost:4020/api";
const OUT = process.env.OUT_DIR ?? "./.bench/eval-ts";
const DB = process.env.EVAL_DB ?? "vnu_trust_eval";
const PG = process.env.PG_CONTAINER ?? "vnu_trust_postgres";
const PGUSER = process.env.DB_USER ?? "vnu_trust";
const SEED = Number(process.env.SEED ?? 20261114);
mkdirSync(OUT, { recursive: true });

// PRNG mulberry32 có hạt giống cố định
let _s = SEED >>> 0;
const rnd = () => { _s = (_s + 0x6D2B79F5) >>> 0; let t = _s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
const ri = (n) => Math.floor(rnd() * n);
const pick = (a) => a[ri(a.length)];
const shuffle = (a) => { const b = [...a]; for (let i = b.length - 1; i > 0; i--) { const j = ri(i + 1); [b[i], b[j]] = [b[j], b[i]]; } return b; };

const hex = (b) => "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const fakeTx = () => "0x" + createHash("sha256").update(randomUUID()).digest("hex");
const canon = (v) => v === null || typeof v !== "object" ? JSON.stringify(v)
  : Array.isArray(v) ? "[" + v.map(canon).join(",") + "]"
  : "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
const sha3 = (v) => hex(sha3_256(new TextEncoder().encode(typeof v === "string" ? v : canon(v))));
const psql = (sql) => execFileSync("docker", ["exec", "-i", PG, "psql", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-U", PGUSER, "-d", DB], { input: sql, encoding: "utf8" });
const clone = (v) => JSON.parse(JSON.stringify(v));

async function call(m, p, b, t) {
  const r = await fetch(TS + p, { method: m,
    headers: { ...(b ? { "content-type": "application/json" } : {}), ...(t ? { authorization: "Bearer " + t } : {}) },
    body: b ? JSON.stringify(b) : undefined });
  const x = await r.text(); let d; try { d = JSON.parse(x); } catch { d = x.slice(0, 300); }
  return { status: r.status, data: d };
}

async function actor(role, label) {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  const address = hex(sha3_256(new Uint8Array([...pub, 0x00])));
  const did = `did:vnu:${role}:${address}`;
  const reg = await call("POST", "/entities/register", { address, publicKeyHex: hex(pub), did, role, label });
  if (reg.status !== 201) throw new Error(`đăng ký ${role}: ${JSON.stringify(reg.data)}`);
  const ch = await call("POST", "/auth/challenge", { address });
  const vf = await call("POST", "/auth/verify", { address, nonce: ch.data.data.nonce, signature: hex(ed25519.sign(new TextEncoder().encode(ch.data.data.message), priv)) });
  if (vf.status !== 200) throw new Error(`đăng nhập ${role}: ${JSON.stringify(vf.data)}`);
  return { pub, address, did, token: vf.data.data.token, sign: (m) => hex(ed25519.sign(new TextEncoder().encode(m), priv)) };
}

const rb = (n) => randomBytes(n).toString("base64");
const envelope = (vcIdHash, holder, issuer) => ({ v: 1, alg: "A256GCM", aad: `vnu-vc:${vcIdHash}`, iv: rb(12), ct: rb(96),
  recipients: [{ kid: holder, role: "holder", epk: rb(32), iv: rb(12), wk: rb(48) }, { kid: issuer, role: "issuer", epk: rb(32), iv: rb(12), wk: rb(48) }] });
const shareBlob = () => ({ v: 1, alg: "A256GCM", iv: rb(12), ct: rb(96) });

async function giveDid(h) {
  const didDoc = { "@context": ["https://www.w3.org/ns/did/v1"], id: h.did,
    verificationMethod: [{ id: `${h.did}#key-1`, type: "Ed25519VerificationKey2020", controller: h.did, publicKeyMultibase: hex(h.pub) }],
    authentication: [`${h.did}#key-1`] };
  const pin = await call("POST", "/ipfs/pin", { json: didDoc, name: "did-doc" }, h.token);
  const ds = await call("POST", "/did/save", { did: h.did, documentCid: pin.data.data.cid, documentHash: sha3(didDoc), docJson: didDoc, txHash: fakeTx() }, h.token);
  if (ds.status !== 201) throw new Error("did/save " + JSON.stringify(ds.data));
}

let onChainSeq = 910000;
const NAMES = ["Cử nhân Công nghệ thông tin", "Kỹ sư Điện tử viễn thông", "Thạc sĩ Khoa học dữ liệu", "Chứng chỉ Ngoại ngữ", "Cử nhân Vật lý", "Kỹ sư Cơ điện tử"];
const FACS = ["Trường Đại học Công nghệ", "Trường Đại học Khoa học Tự nhiên", "Trường Đại học Kinh tế", "Trường Đại học Ngoại ngữ"];
async function issueVc(issuer, holder, i) {
  const vcId = `urn:uuid:${randomUUID()}`;
  const issuedAt = new Date().toISOString();
  const vc = { "@context": ["https://www.w3.org/2018/credentials/v1", { vnu: "https://vnu.edu.vn/credentials/v1#" }],
    id: vcId, type: ["VerifiableCredential", "VNUDegreeCredential"], issuer: issuer.did, issuanceDate: issuedAt,
    credentialSubject: { id: holder.did, "vnu:studentId": String(22000000 + ri(999999)), "vnu:degreeName": `${pick(NAMES)} (${i + 1})`,
      "vnu:faculty": pick(FACS), "vnu:gpa": (2 + rnd() * 2).toFixed(2), "vnu:graduationYear": String(2018 + ri(9)) } };
  const p = await call("POST", "/ipfs/pin", { json: envelope(sha3(vcId), holder.address, issuer.address), name: "vc" }, issuer.token);
  const r = await call("POST", "/issuer/credentials", { vcId, onChainVcId: onChainSeq++, holderDid: holder.did, holderAddress: holder.address,
    vcType: 1, ipfsCid: p.data.data.cid, vcIdHash: sha3(vcId), contentHash: sha3(vc), proofValue: issuer.sign(canon(vc)),
    issuedAt, expiresAt: null, txHash: fakeTx() }, issuer.token);
  if (r.status !== 201) throw new Error("issue " + JSON.stringify(r.data));
  return { vcId, vc };
}

/** Tạo VP + liên kết cho `holder` từ danh sách VC; trả { vp, token, vpId }. */
async function makeShare(holder, vcs, vpOverride) {
  const vp = vpOverride ?? { "@context": ["https://www.w3.org/2018/credentials/v1"], type: ["VerifiablePresentation"], holder: holder.did,
    verifiableCredential: vcs.map((x) => x.vc), created: new Date().toISOString() };
  const p = await call("POST", "/ipfs/pin", { json: shareBlob(), name: "vp" }, holder.token);
  const vpId = `urn:uuid:${randomUUID()}`;
  const r = await call("POST", "/holder/presentations", { vpId, verifierDid: null, vcIds: vcs.map((x) => x.vcId), ipfsCid: p.data.data.cid,
    vpHash: sha3(vp), proofValue: holder.sign(canon(vp)), challenge: null, ttlSeconds: 86400 }, holder.token);
  if (r.status !== 201) throw new Error("vp " + JSON.stringify(r.data));
  return { vp, token: r.data.data.share.token, vpId };
}

// ---- biến đổi
const FIELDS = { gpa: "vnu:gpa", degreeName: "vnu:degreeName", graduationYear: "vnu:graduationYear", studentId: "vnu:studentId", faculty: "vnu:faculty" };
const newVal = (f, old) => {
  for (;;) {
    const v = f === "gpa" ? (2 + rnd() * 2).toFixed(2) : f === "degreeName" ? `${pick(NAMES)} (sua)` : f === "graduationYear" ? String(2010 + ri(20))
      : f === "studentId" ? String(10000000 + ri(89999999)) : pick(FACS);
    if (v !== old) return v;
  }
};
function tamperOne(vp) {
  const t = clone(vp);
  const f = pick(Object.keys(FIELDS));
  const vc = pick(t.verifiableCredential);
  const old = vc.credentialSubject[FIELDS[f]];
  const neu = newVal(f, old);
  vc.credentialSubject[FIELDS[f]] = neu;
  return { vp: t, desc: `${f}: "${old}" -> "${neu}" (VC ${vc.id.slice(9, 17)})` };
}
const shuffleKeys = (v) => v === null || typeof v !== "object" ? v : Array.isArray(v) ? v.map(shuffleKeys)
  : Object.fromEntries(shuffle(Object.keys(v)).map((k) => [k, shuffleKeys(v[k])]));
const toNFD = (v) => typeof v === "string" ? v.normalize("NFD") : v === null || typeof v !== "object" ? v : Array.isArray(v) ? v.map(toNFD)
  : Object.fromEntries(Object.entries(v).map(([k, x]) => [k, toNFD(x)]));

// ---- ghi nhận
const scen = [];
function newScen(id, mota, n) {
  const s = { id, mota, n, overallValid: { true: 0, false: 0 }, stepFail: Object.fromEntries([1, 2, 3, 4, 5, 6, 7].map((i) => [String(i), 0])), httpStatus: {}, vidu: null };
  scen.push(s); return s;
}
async function verify(s, token, vp, vidu) {
  const r = await call("POST", `/verify/share/${token}`, { vp });
  s.httpStatus[r.status] = (s.httpStatus[r.status] ?? 0) + 1;
  if (r.status === 200) {
    const rep = r.data.data;
    s.overallValid[String(rep.overallValid)]++;
    if (rep.checks.length !== 7) throw new Error(`báo cáo có ${rep.checks.length} bước, kỳ vọng 7`);
    rep.checks.forEach((c, i) => { if (!c.passed) s.stepFail[String(i + 1)]++; });
    if (!s.vidu && vidu) s.vidu = { bienThe: vidu, hopLe: rep.overallValid, buocHong: rep.checks.map((c, i) => c.passed ? null : `${i + 1}: ${c.name}`).filter(Boolean) };
  } else if (!s.vidu) s.vidu = { bienThe: vidu, http: r.status, thongDiep: typeof r.data === "string" ? r.data : r.data?.error ?? r.data };
  return r;
}
const log = (s) => console.log(`   ${s.id}: n=${s.n} hợp lệ=${s.overallValid.true} không=${s.overallValid.false} hỏng/bước=${JSON.stringify(s.stepFail)} http=${JSON.stringify(s.httpStatus)}`);

// ================================================================
const issuer = await actor("issuer", "Truong thanh vien (tamper)");
const A = await actor("holder", "Nan nhan A");
const B = await actor("holder", "Ke khac B");
await giveDid(A); await giveDid(B);
const vcs = [];
for (let i = 0; i < 8; i++) vcs.push(await issueVc(issuer, A, i));
console.log("   ✓ dựng: 1 issuer, 2 holder, 8 VC cho A");

// Nhóm liên kết gốc (20): mỗi cái một tập con ngẫu nhiên 1..8 VC theo thứ tự ngẫu nhiên
const pool = [];
for (let i = 0; i < 20; i++) pool.push(await makeShare(A, shuffle(vcs).slice(0, 1 + ri(8))));
const fromPool = (i) => pool[i % pool.length];

// S0
let s = newScen("S0", "VP nguyên vẹn, liên kết gốc", 20);
for (let i = 0; i < 20; i++) await verify(s, pool[i].token, pool[i].vp, "VP gốc");
log(s);

// S1
s = newScen("S1", "Chủ thể tự sửa 1 trường credentialSubject rồi tạo liên kết MỚI cho VP đã sửa (hash và chữ ký tính lại)", 100);
for (let i = 0; i < 100; i++) {
  const base = fromPool(i); const t = tamperOne(base.vp);
  const used = t.vp.verifiableCredential.map((v) => vcs.find((x) => x.vcId === v.id));
  const sh = await makeShare(A, used, t.vp);
  await verify(s, sh.token, t.vp, t.desc);
}
log(s);

// S2
s = newScen("S2", "Sửa trên đường truyền: gửi VP đã sửa 1 trường lên liên kết gốc", 100);
for (let i = 0; i < 100; i++) { const base = fromPool(i); const t = tamperOne(base.vp); await verify(s, base.token, t.vp, t.desc); }
log(s);

// S3
s = newScen("S3", "Đảo ngẫu nhiên thứ tự khoá ở mọi cấp rồi gửi lên liên kết gốc (không đổi nghĩa)", 100);
for (let i = 0; i < 100; i++) { const base = fromPool(i); const v = shuffleKeys(base.vp); await verify(s, base.token, v, `thứ tự khoá cấp gốc: ${Object.keys(v).join(",")}`); }
log(s);

// S4
s = newScen("S4", "Chuẩn hoá Unicode NFC -> NFD mọi chuỗi trong VP, gửi lên liên kết gốc", 20);
for (let i = 0; i < 20; i++) { const base = fromPool(i); const v = toNFD(base.vp);
  const ex = v.verifiableCredential[0].credentialSubject["vnu:degreeName"];
  await verify(s, base.token, v, `degreeName NFD: ${JSON.stringify(ex)} (${[...ex].length} điểm mã, NFC ${ex.normalize("NFC").length})`); }
log(s);

// S5
s = newScen("S5", "VC đã bị thu hồi qua tuyến issuer (mỗi lần 1 VC + 1 liên kết mới), rồi xác minh", 20);
for (let i = 0; i < 20; i++) {
  const one = await issueVc(issuer, A, 100 + i);
  const sh = await makeShare(A, [one]);
  const rv = await call("POST", `/issuer/credentials/${encodeURIComponent(one.vcId)}/revoke`, { reason: "kiem thu gian lan", txHash: fakeTx() }, issuer.token);
  if (rv.status !== 200) throw new Error("revoke " + JSON.stringify(rv.data));
  await verify(s, sh.token, sh.vp, `thu hồi VC ${one.vcId.slice(9, 17)}`);
}
log(s);

// S6
s = newScen("S6", "Issuer bị đình chỉ trong chỉ mục (entities.role issuer -> holder), xác minh liên kết gốc; đã trả lại sau đó", 20);
psql(`UPDATE entities SET role='holder' WHERE address='${issuer.address}';`);
try { for (let i = 0; i < 20; i++) await verify(s, pool[i].token, pool[i].vp, "issuer bị đình chỉ trong chỉ mục"); }
finally { psql(`UPDATE entities SET role='issuer' WHERE address='${issuer.address}';`); }
const back = psql(`SELECT role FROM entities WHERE address='${issuer.address}';`).trim();
if (back !== "issuer") throw new Error("không trả lại được vai trò issuer: " + back);
log(s);

// S7
s = newScen("S7", "Holder B tạo liên kết chứa vcId của A (POST /holder/presentations)", 10);
for (let i = 0; i < 10; i++) {
  const vp = { "@context": ["https://www.w3.org/2018/credentials/v1"], type: ["VerifiablePresentation"], holder: B.did, verifiableCredential: [vcs[i % 8].vc], created: new Date().toISOString() };
  const p = await call("POST", "/ipfs/pin", { json: shareBlob(), name: "vp" }, B.token);
  const r = await call("POST", "/holder/presentations", { vpId: `urn:uuid:${randomUUID()}`, verifierDid: null, vcIds: [vcs[i % 8].vcId], ipfsCid: p.data.data.cid,
    vpHash: sha3(vp), proofValue: B.sign(canon(vp)), challenge: null, ttlSeconds: 3600 }, B.token);
  s.httpStatus[r.status] = (s.httpStatus[r.status] ?? 0) + 1;
  if (!s.vidu) s.vidu = { http: r.status, thongDiep: r.data?.error ?? r.data };
}
log(s);

writeFileSync(`${OUT}/tamper.json`, JSON.stringify({ meta: { at: new Date().toISOString(), seed: SEED, backend: "TS", verifyOnchain: false,
  buoc: ["1 Tải VP từ IPFS", "2 Toàn vẹn nội dung VP", "3 Chữ ký người trình bày", "4 DID còn hiệu lực", "5 Tất cả chứng chỉ còn hiệu lực", "6 Nội dung khớp bản neo", "7 Đơn vị cấp còn tin cậy (cảnh báo)"] }, scenarios: scen }, null, 2));
console.log(`  → ${OUT}/tamper.json`);
