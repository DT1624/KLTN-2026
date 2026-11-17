/**
 * Thí nghiệm D và E — đo qua HTTP trên hai backend chạy với CSDL cách ly.
 *
 *   node load.mjs setup                tạo vai trò, DID, 8 văn bằng, 4 bản trình bày (k = 1, 2, 4, 8)
 *   node load.mjs isolation <nhãn>     E: lặp phép đo ở c = 8 để lượng hoá độ phân tán
 *   node load.mjs scale                D: nạp thêm dữ liệu theo bậc, đo thời gian phục vụ ở c = 1
 *
 * Trạng thái giữa các pha (token, mã chia sẻ) nằm ở $OUT_DIR/state.json.
 * Dữ liệu độn được nạp thẳng bằng SQL qua `docker exec … psql`, vì gọi API để
 * tạo 100.000 văn bằng sẽ đo tốc độ API thay vì đo thứ cần đo.
 */
import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";
import { randomUUID, createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";

const TS = process.env.TS_BASE ?? "http://localhost:4020/api";
const GO = process.env.GO_BASE ?? "http://localhost:4021/api";
const OUT = process.env.OUT_DIR ?? "./.bench/eval";
const DB = process.env.EVAL_DB ?? "vnu_trust_eval";
const PG = process.env.PG_CONTAINER ?? "vnu_trust_postgres";
const PGUSER = process.env.DB_USER ?? "vnu_trust";
const BACKENDS = (process.env.BACKENDS ?? "TS,Go").split(",").map((x) => x.trim().toUpperCase());
const useBe = (name) => BACKENDS.includes(name.toUpperCase());
mkdirSync(OUT, { recursive: true });

const hex = (b) => "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const fakeTx = () => "0x" + createHash("sha256").update(randomUUID()).digest("hex");
const canon = (v) => v === null || typeof v !== "object" ? JSON.stringify(v)
  : Array.isArray(v) ? "[" + v.map(canon).join(",") + "]"
  : "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
const sha3 = (v) => hex(sha3_256(new TextEncoder().encode(typeof v === "string" ? v : canon(v))));
const pct = (s, p) => s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)];
const mean = (a) => a.reduce((x, y) => x + y, 0) / a.length;
const sd = (a) => { const m = mean(a); return Math.sqrt(a.reduce((s, x) => s + (x - m) ** 2, 0) / (a.length - 1)); };
const median = (a) => { const s = [...a].sort((x, y) => x - y); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const psql = (sql) => execFileSync("docker", ["exec", "-i", PG, "psql", "-q", "-At", "-v", "ON_ERROR_STOP=1", "-U", PGUSER, "-d", DB], { input: sql, encoding: "utf8", maxBuffer: 64 << 20 });

async function call(base, m, p, b, t) {
  const r = await fetch(base + p, { method: m,
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
  const reg = await call(TS, "POST", "/entities/register", { address, publicKeyHex: hex(pub), did, role, label });
  if (reg.status !== 201) throw new Error(`đăng ký ${role}: ${JSON.stringify(reg.data)}`);
  const login = async (base) => {
    const ch = await call(base, "POST", "/auth/challenge", { address });
    const vf = await call(base, "POST", "/auth/verify", { address, nonce: ch.data.data.nonce, signature: hex(ed25519.sign(new TextEncoder().encode(ch.data.data.message), priv)) });
    if (vf.status !== 200) throw new Error(`đăng nhập ${role}: ${JSON.stringify(vf.data)}`);
    return vf.data.data.token;
  };
  return { priv, pub, address, did, token: await login(TS), sign: (m) => hex(ed25519.sign(new TextEncoder().encode(m), priv)) };
}

// P3 (13/11/2026): IPFS chỉ giữ phong bì / bản trình bày ĐÃ MÃ HOÁ; backend chỉ kiểm cấu
// trúc nên dùng byte ngẫu nhiên đúng kích thước. Người xác minh gửi bản rõ vp khi xác minh.
const rb = (n) => randomBytes(n).toString("base64");
const envelope = (vcIdHash, holder, issuer) => ({ v: 1, alg: "A256GCM", aad: `vnu-vc:${vcIdHash}`, iv: rb(12), ct: rb(96),
  recipients: [{ kid: holder, role: "holder", epk: rb(32), iv: rb(12), wk: rb(48) }, { kid: issuer, role: "issuer", epk: rb(32), iv: rb(12), wk: rb(48) }] });
const shareBlob = () => ({ v: 1, alg: "A256GCM", iv: rb(12), ct: rb(96) });

// ============================================================ setup
async function setup() {
  const issuer = await actor("issuer", "Truong thanh vien (danh gia)");
  const holder = await actor("holder", "Nguoi hoc (danh gia)");
  const didDoc = { "@context": ["https://www.w3.org/ns/did/v1"], id: holder.did,
    verificationMethod: [{ id: `${holder.did}#key-1`, type: "Ed25519VerificationKey2020", controller: holder.did, publicKeyMultibase: hex(holder.pub) }],
    authentication: [`${holder.did}#key-1`] };
  const pin = await call(TS, "POST", "/ipfs/pin", { json: didDoc, name: "did-doc" }, holder.token);
  const ds = await call(TS, "POST", "/did/save", { did: holder.did, documentCid: pin.data.data.cid, documentHash: sha3(didDoc), docJson: didDoc, txHash: fakeTx() }, holder.token);
  if (ds.status !== 201) throw new Error("did/save " + JSON.stringify(ds.data));

  const vcs = [];
  for (let i = 0; i < 8; i++) {
    const vcId = `urn:uuid:${randomUUID()}`;
    const issuedAt = new Date().toISOString();
    const vc = { "@context": ["https://www.w3.org/2018/credentials/v1", { vnu: "https://vnu.edu.vn/credentials/v1#" }],
      id: vcId, type: ["VerifiableCredential", "VNUDegreeCredential"], issuer: issuer.did, issuanceDate: issuedAt,
      credentialSubject: { id: holder.did, "vnu:studentId": "22028334", "vnu:degreeName": `Chứng chỉ ${i + 1}`,
        "vnu:faculty": "Trường Đại học Công nghệ", "vnu:gpa": "3.42", "vnu:graduationYear": "2026" } };
    const p = await call(TS, "POST", "/ipfs/pin", { json: envelope(sha3(vcId), holder.address, issuer.address), name: "vc" }, issuer.token);
    const r = await call(TS, "POST", "/issuer/credentials", { vcId, onChainVcId: 900000 + i, holderDid: holder.did, holderAddress: holder.address,
      vcType: 1, ipfsCid: p.data.data.cid, vcIdHash: sha3(vcId), contentHash: sha3(vc), proofValue: issuer.sign(canon(vc)),
      issuedAt, expiresAt: null, txHash: fakeTx() }, issuer.token);
    if (r.status !== 201) throw new Error("issue " + JSON.stringify(r.data));
    vcs.push({ vcId, vc });
  }
  const shares = {};
  const vps = {};
  for (const k of [1, 2, 4, 8]) {
    const vp = { "@context": ["https://www.w3.org/2018/credentials/v1"], type: ["VerifiablePresentation"], holder: holder.did,
      verifiableCredential: vcs.slice(0, k).map((x) => x.vc), created: new Date().toISOString() };
    const p = await call(TS, "POST", "/ipfs/pin", { json: shareBlob(), name: "vp" }, holder.token);
    const r = await call(TS, "POST", "/holder/presentations", { vpId: `urn:uuid:${randomUUID()}`, verifierDid: null,
      vcIds: vcs.slice(0, k).map((x) => x.vcId), ipfsCid: p.data.data.cid, vpHash: sha3(vp), proofValue: holder.sign(canon(vp)),
      challenge: null, ttlSeconds: 86400 }, holder.token);
    if (r.status !== 201) throw new Error("vp " + JSON.stringify(r.data));
    shares[k] = r.data.data.share.token;
    vps[k] = vp;
  }
  // Kiểm tra trước khi đo: một phép đo trên tuyến trả lỗi thì chỉ đo tốc độ trả lỗi.
  for (const base of [TS, GO].filter((_, i) => useBe(["TS", "GO"][i]))) {
    const rep = await call(base, "POST", `/verify/share/${shares[8]}`, { vp: vps[8] });
    if (rep.status !== 200 || !rep.data.data.overallValid) throw new Error(`xác minh k=8 ở ${base} không hợp lệ: ${JSON.stringify(rep.data).slice(0, 300)}`);
  }
  writeFileSync(`${OUT}/state.json`, JSON.stringify({ holderDid: holder.did, holderPriv: hex(holder.priv), holderAddress: holder.address, token: holder.token, shares, vps }, null, 2));
  console.log("   ✓ đã dựng: 1 issuer, 1 holder, 8 VC, 4 VP — xác minh k=8 hợp lệ ở cả hai backend");
}

const state = () => JSON.parse(readFileSync(`${OUT}/state.json`, "utf8"));
const routes = (s) => ({
  "/did/resolve": { m: "GET", p: `/did/resolve?did=${encodeURIComponent(s.holderDid)}` },
  "/auth/me": { m: "GET", p: "/auth/me", auth: true },
  "/holder/credentials": { m: "GET", p: "/holder/credentials", auth: true },
  "verify k=1": { m: "POST", p: `/verify/share/${s.shares[1]}`, body: { vp: s.vps[1] } },
  "verify k=2": { m: "POST", p: `/verify/share/${s.shares[2]}`, body: { vp: s.vps[2] } },
  "verify k=4": { m: "POST", p: `/verify/share/${s.shares[4]}`, body: { vp: s.vps[4] } },
  "verify k=8": { m: "POST", p: `/verify/share/${s.shares[8]}`, body: { vp: s.vps[8] } },
});

async function run(base, r, token, n, conc) {
  const lat = []; let next = 0, bad = 0;
  const t0 = performance.now();
  await Promise.all(Array.from({ length: conc }, async () => {
    while (next < n) {
      next++;
      const s = performance.now();
      try {
        const res = await fetch(base + r.p, {
          method: r.m,
          headers: { ...(r.auth ? { authorization: "Bearer " + token } : {}), ...(r.body ? { "content-type": "application/json" } : {}) },
          body: r.body ? JSON.stringify(r.body) : undefined,
        });
        await res.text();
        if (res.status >= 400) bad++;
      } catch { bad++; }
      lat.push(performance.now() - s);
    }
  }));
  const wall = performance.now() - t0;
  const sorted = lat.sort((a, b) => a - b);
  return { n, rps: n / (wall / 1000), p50: pct(sorted, 50), p95: pct(sorted, 95), p99: pct(sorted, 99), mean: mean(lat), bad };
}

/** Token của backend nào thì dùng cho backend đó — cả hai dùng chung JWT_SECRET nên dùng chéo được. */
async function tokenFor(s) {
  return s.token;
}

// ============================================================ E: độ phân tán khi ghim/không ghim CPU
async function isolation(label) {
  const s = state(); const R = routes(s); const token = await tokenFor(s);
  const REPEATS = Number(process.env.REPEATS ?? 10), N = Number(process.env.N ?? 1000), CONC = Number(process.env.CONC ?? 8);
  const rows = [];
  for (const [be, base] of [["TS", TS], ["GO", GO]].filter(([b]) => useBe(b))) {
    for (const name of ["/did/resolve", "/auth/me", "verify k=1"]) {
      await run(base, R[name], token, 200, CONC); // khởi động
      const reps = [];
      for (let i = 0; i < REPEATS; i++) { reps.push(await run(base, R[name], token, N, CONC)); await sleep(200); }
      const p95 = reps.map((x) => x.p95), rps = reps.map((x) => x.rps);
      const row = { label, backend: be, route: name, repeats: REPEATS, n: N, conc: CONC,
        p95: { mean: mean(p95), sd: sd(p95), cv: (sd(p95) / mean(p95)) * 100, min: Math.min(...p95), max: Math.max(...p95), median: median(p95) },
        rps: { mean: mean(rps), sd: sd(rps), cv: (sd(rps) / mean(rps)) * 100, median: median(rps) },
        p50: median(reps.map((x) => x.p50)), bad: reps.reduce((a, x) => a + x.bad, 0), raw: reps };
      rows.push(row);
      console.log(`   [${label}] ${be} ${name}: p95 ${row.p95.mean.toFixed(2)} ± ${row.p95.sd.toFixed(2)} ms (CV ${row.p95.cv.toFixed(1)}%), ${row.rps.median.toFixed(0)} yc/s, lỗi ${row.bad}`);
    }
  }
  const f = `${OUT}/isolation.json`;
  const prev = existsSync(f) ? JSON.parse(readFileSync(f, "utf8")) : { meta: {}, data: [] };
  prev.data = prev.data.filter((x) => x.label !== label).concat(rows);
  prev.meta[label] = { at: new Date().toISOString(), cpusetServices: process.env.CPUSET_SVC ?? "", cpusetLoad: process.env.CPUSET_LOAD ?? "" };
  writeFileSync(f, JSON.stringify(prev, null, 2));
}

// ============================================================ D: quy mô dữ liệu
function fill(from, to) {
  // Mỗi "bản ghi" = 1 thực thể holder + 1 DID Document + 1 văn bằng, rải cho 12 đơn vị cấp
  // (9 trường thành viên + 3 trường trực thuộc). P3: không còn cột vc_json — nội dung
  // văn bằng chỉ nằm trong phong bì mã hoá trên IPFS.
  psql(`
INSERT INTO entities (address, public_key_hex, did, role, label)
SELECT '0x' || 'e' || lpad(to_hex(i), 63, '0'), '0x' || md5(i::text) || md5((i+1)::text), 'did:vnu:holder:0x' || 'e' || lpad(to_hex(i), 63, '0'), 'holder', 'Nguoi hoc ' || i
FROM generate_series(${from}, ${to - 1}) AS i;
INSERT INTO did_documents (entity_id, did, document_cid, document_hash, doc_json, tx_hash)
SELECT e.id, e.did, 'bafkrei' || substr(md5(e.did) || md5(e.address), 1, 52), '0x' || md5(e.did) || md5(e.label),
       jsonb_build_object('@context', jsonb_build_array('https://www.w3.org/ns/did/v1'), 'id', e.did), '0x' || md5(e.address) || md5(e.did)
FROM entities e WHERE e.label ~ '^Nguoi hoc [0-9]+$' AND substring(e.label from 11)::int BETWEEN ${from} AND ${to - 1};
INSERT INTO credentials (vc_id, on_chain_vc_id, issuer_did, issuer_address, holder_did, holder_address, vc_type, ipfs_cid,
                         vc_id_hash, content_hash, proof_value, status, issued_at, tx_hash)
SELECT 'urn:uuid:' || gen_random_uuid(), 1000000 + i,
       'did:vnu:issuer:0x' || 'a' || lpad(to_hex(i % 12), 63, '0'), '0x' || 'a' || lpad(to_hex(i % 12), 63, '0'),
       'did:vnu:holder:0x' || 'e' || lpad(to_hex(i), 63, '0'), '0x' || 'e' || lpad(to_hex(i), 63, '0'), 1 + (i % 6),
       'bafkrei' || substr(md5(i::text) || md5((i*7)::text), 1, 52), '0x' || md5(i::text) || md5((i*3)::text),
       '0x' || md5((i*5)::text) || md5((i*11)::text), '0x' || md5((i*13)::text) || md5((i*17)::text) || md5((i*19)::text) || md5((i*23)::text),
       (ARRAY['active','active','active','active','active','active','active','active','revoked','suspended'])[1 + i % 10]::vc_status,
       now() - (i || ' minutes')::interval, '0x' || md5((i*29)::text) || md5((i*31)::text)
FROM generate_series(${from}, ${to - 1}) AS i;
VACUUM ANALYZE entities; VACUUM ANALYZE did_documents; VACUUM ANALYZE credentials;`);
}

function explain() {
  const plan = psql("EXPLAIN (ANALYZE, FORMAT JSON) SELECT status FROM credentials WHERE on_chain_vc_id = 900003;");
  const p = JSON.parse(plan)[0];
  return { node: p.Plan["Node Type"], execMs: p["Execution Time"], planMs: p["Planning Time"], rowsRemoved: p.Plan["Rows Removed by Filter"] ?? 0 };
}

async function measure(level, tag, names) {
  const s = state(); const R = routes(s); const token = await tokenFor(s);
  const rows = [];
  for (const [be, base] of [["TS", TS], ["GO", GO]].filter(([b]) => useBe(b))) {
    for (const name of names) {
      const probe = await run(base, R[name], token, 10, 1);
      // Ngân sách khoảng 12 giây mỗi cấu hình, kẹp trong [40, 300] mẫu.
      const n = Math.max(40, Math.min(300, Math.round(12000 / Math.max(probe.p50, 0.5))));
      const r = await run(base, R[name], token, n, 1);
      rows.push({ level, tag, backend: be, route: name, ...r });
      console.log(`   [N=${level}${tag ? " " + tag : ""}] ${be} ${name}: p50 ${r.p50.toFixed(2)} ms, p95 ${r.p95.toFixed(2)} ms (n=${n}, lỗi ${r.bad})`);
    }
  }
  return rows;
}

async function scale() {
  const LEVELS = (process.env.LEVELS ?? "0,1000,10000,100000").split(",").map(Number);
  const NAMES = ["/did/resolve", "/holder/credentials", "verify k=1", "verify k=8"];
  const out = { meta: { at: new Date().toISOString(), levels: LEVELS, conc: 1 }, data: [], explain: [], size: [] };
  let have = 0;
  // Lược đồ (db/schema.sql) đã có idx_vc_onchain; thí nghiệm bóc tách cần nhánh không chỉ mục thật.
  psql("DROP INDEX IF EXISTS idx_vc_onchain;");
  for (const L of LEVELS) {
    if (L > have) { const t0 = Date.now(); fill(have, L); console.log(`   · nạp ${L - have} bản ghi trong ${((Date.now() - t0) / 1000).toFixed(1)} s`); have = L; }
    out.explain.push({ level: L, index: false, ...explain() });
    out.size.push({ level: L, credentialsBytes: Number(psql("SELECT pg_total_relation_size('credentials');").trim()) });
    out.data.push(...await measure(L, "", NAMES));
  }
  // Bóc tách: thêm chỉ mục trên on_chain_vc_id ở bậc lớn nhất rồi đo lại đúng các tuyến xác minh.
  psql("CREATE INDEX IF NOT EXISTS idx_vc_onchain ON credentials(on_chain_vc_id); ANALYZE credentials;");
  out.explain.push({ level: have, index: true, ...explain() });
  out.data.push(...await measure(have, "index", ["/holder/credentials", "verify k=1", "verify k=2", "verify k=4", "verify k=8"]));
  psql("DROP INDEX IF EXISTS idx_vc_onchain; ANALYZE credentials;");
  out.data.push(...await measure(have, "noindex", ["verify k=2", "verify k=4"]));
  psql("CREATE INDEX IF NOT EXISTS idx_vc_onchain ON credentials(on_chain_vc_id); ANALYZE credentials;");
  writeFileSync(`${OUT}/scale.json`, JSON.stringify(out, null, 2));
  console.log(`  → ${OUT}/scale.json`);
}

// ============================================================ sweep: mức đồng thời x tuyến (chỉ TS)
async function sweep() {
  const s = state(); const R = routes(s); const token = await tokenFor(s);
  const CONCS = (process.env.CONCS ?? "1,2,4,8,16,32,64").split(",").map(Number);
  const REPEATS = Number(process.env.REPEATS ?? 5), N = Number(process.env.N ?? 1000);
  const NAMES = ["/did/resolve", "/auth/me", "/holder/credentials", "verify k=1", "verify k=8"];
  const st = (a) => ({ median: median(a), min: Math.min(...a), max: Math.max(...a) });
  const data = [];
  for (const name of NAMES) {
    await run(TS, R[name], token, 200, 8); // khởi động, bỏ kết quả
    for (const conc of CONCS) {
      const runs = [];
      for (let i = 0; i < REPEATS; i++) {
        const r = await run(TS, R[name], token, N, conc);
        runs.push({ rps: r.rps, p50: r.p50, p95: r.p95, p99: r.p99, mean: r.mean, bad: r.bad });
        await sleep(200);
      }
      const row = { route: name, conc, runs, rps: st(runs.map((x) => x.rps)), p50: st(runs.map((x) => x.p50)),
        p95: st(runs.map((x) => x.p95)), bad: runs.reduce((a, x) => a + x.bad, 0) };
      data.push(row);
      console.log(`   [sweep] ${name} c=${conc}: ${row.rps.median.toFixed(0)} yc/s, p95 ${row.p95.median.toFixed(1)} ms, lỗi ${row.bad}`);
    }
  }
  writeFileSync(`${OUT}/sweep.json`, JSON.stringify({ meta: { at: new Date().toISOString(), repeats: REPEATS, n: N, concs: CONCS,
    cpusetServices: process.env.CPUSET_SVC ?? "", cpusetLoad: process.env.CPUSET_LOAD ?? "", backend: "TS" }, data }, null, 2));
  console.log(`  → ${OUT}/sweep.json`);
}

const [phase, arg] = process.argv.slice(2);
if (phase === "setup") await setup();
else if (phase === "isolation") await isolation(arg ?? "baseline");
else if (phase === "sweep") await sweep();
else if (phase === "scale") await scale();
else { console.error("pha: setup | isolation <nhãn> | sweep | scale"); process.exit(2); }
