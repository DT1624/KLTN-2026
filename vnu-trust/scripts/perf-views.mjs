// Đo SỐ LẦN GỌI VIEW lên fullnode cho mỗi yêu cầu, và độ trễ khi mỗi lần gọi tốn một
// vòng mạng — P5 (13/11/2026). "Đo trước khi tối ưu" (bài học #18).
//
//   cd frontend && cp ../scripts/perf-views.mjs t.mjs && LATENCY_MS=30 node t.mjs; rm t.mjs
//
// Vì sao fullnode GIẢ: chỉ số quyết định là số lần gọi (N+1) — đếm chính xác được ở
// đây, còn bắn tải vào fullnode công khai thì vừa nhiễu vừa thiếu lịch sự. Độ trễ giả
// (LATENCY_MS, mặc định 30 ms ≈ một vòng tới fullnode testnet) cho thấy N lần gọi biến
// thành bao nhiêu mili-giây.
//
// Quy trình: (1) gieo dữ liệu qua backend chạy OFFLINE trên CSDL riêng; (2) dựng lại hai
// backend ở chế độ NGHIÊM NGẶT trỏ vào fullnode giả; (3) mỗi tuyến: đếm view của 1 yêu
// cầu, rồi đo N_REQ yêu cầu tuần tự. Kết quả ghi ra PERF_OUT (JSON) để so trước / sau.
import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";
import { spawn, execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { randomBytes, randomUUID, createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const ROOT = new URL("../", import.meta.url).pathname.replace(/frontend\/$/, "");
const LATENCY = Number(process.env.LATENCY_MS ?? 30);
const N_REQ = Number(process.env.N_REQ ?? 30);
const N_VC = 20, K_VP = 8, N_SUB = 10;
const DB = "vnu_trust_perf";
const OUT = process.env.PERF_OUT ?? `${ROOT}.bench/perf-views.json`;
const CONTRACT = readFileSync(`${ROOT}chain.env`, "utf8").match(/^CONTRACT_ADDRESS=(\S+)/m)[1].toLowerCase();

const hex = (b) => "0x" + Buffer.from(b).toString("hex");
const canon = (v) => v === null || typeof v !== "object" ? JSON.stringify(v)
  : Array.isArray(v) ? "[" + v.map(canon).join(",") + "]"
    : "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
const sha3 = (v) => hex(sha3_256(new TextEncoder().encode(typeof v === "string" ? v : canon(v))));
const b64 = (n) => randomBytes(n).toString("base64");
const norm = (a) => "0x" + String(a).replace(/^0x/, "").toLowerCase().padStart(64, "0");
const psql = (sql, db = "postgres") => execFileSync("docker", ["exec", "-i", "vnu_trust_postgres", "psql", "-q", "-v", "ON_ERROR_STOP=1", "-U", "vnu_trust", "-d", db, "-c", sql]);

// ---------- dịch vụ ----------
const procs = [];
function start(lang, port, env) {
  const [cmd, args, cwd] = lang === "TS" ? ["npx", ["tsx", "src/server.ts"], `${ROOT}backend`] : ["./run.sh", [], `${ROOT}backend-go`];
  const p = spawn(cmd, args, { cwd, detached: true, stdio: "ignore",
    env: { ...process.env, DB_NAME: DB, PORT: String(port), LOG_LEVEL: "warn", RATE_LIMIT_PER_MIN: "1000000", AUTH_RATE_LIMIT_PER_MIN: "100000", ...env } });
  procs.push(p);
  return p;
}
const stop = (p) => { try { process.kill(-p.pid, "SIGTERM"); } catch { /* đã dừng */ } };
async function waitUp(port) {
  for (let i = 0; i < 240; i++) {
    try { if ((await fetch(`http://localhost:${port}/health`)).ok) return; } catch { /* chưa lên */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`cổng ${port} không lên`);
}
async function call(base, method, path, body, token) {
  const r = await fetch(base + path, { method,
    headers: { ...(body ? { "content-type": "application/json" } : {}), ...(token ? { authorization: "Bearer " + token } : {}) },
    body: body ? JSON.stringify(body) : undefined });
  const t = await r.text(); let data; try { data = JSON.parse(t); } catch { data = t; }
  return { status: r.status, data };
}

// ---------- fullnode giả có bộ đếm ----------
const counts = new Map();
let world = { admins: new Set(), issuers: new Set(), delegator: null, subs: new Set(), vcs: new Map() };
const short = (a) => "0x" + norm(a).slice(2).replace(/^0+/, "");
function view(name, args) {
  switch (name) {
    case "authority::is_active_admin": return [world.admins.has(norm(args[0]))];
    case "authority::is_active_issuer": return [world.issuers.has(norm(args[0]))];
    case "authority::can_delegate": return [norm(args[0]) === world.delegator || world.admins.has(norm(args[0]))];
    case "authority::get_root_admin": return [short(CONTRACT)];
    case "authority::get_pending_root": return ["0x0"];
    case "authority::get_delegator": return [world.subs.has(norm(args[0])) ? short(world.delegator) : "0x0"];
    case "authority::get_info": return world.issuers.has(norm(args[0])) || world.subs.has(norm(args[0]))
      ? [short(CONTRACT), "1", "0x", "0x", "0", 1] : null;
    case "authority::stats": return ["1", String(world.issuers.size)];
    case "did_registry::has_active_did": return [true];
    case "did_registry::total_dids": case "vc_registry::total_vcs": return ["100"];
    case "vc_registry::get_vc_status": return [1];
    case "vc_registry::get_live_counts": return ["1", "1"];
    case "vc_registry::get_replacement": return [false, "0"];
    case "vc_registry::verify_integrity": {
      const h = world.vcs.get(String(args[0]));
      return [h !== undefined && h === String(args[1]).toLowerCase()];
    }
    case "vc_registry::get_vcs_paginated": {
      const out = [];
      for (let id = Number(args[0]); id < Number(args[0]) + Number(args[1]); id++) {
        if (!world.vcs.has(String(id))) continue;
        out.push({ id: String(id), status: 1, content_hash: world.vcs.get(String(id)), expires_at: "0" });
      }
      return [out];
    }
    default: return null;
  }
}
const mock = createServer((req, res) => {
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => setTimeout(() => {
    const send = (code, obj) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); };
    if (req.url === "/v1/" || req.url === "/v1") return send(200, { chain_id: 250, ledger_version: "1" });
    if (req.url === "/v1/view" && req.method === "POST") {
      const { function: fn, arguments: args } = JSON.parse(body);
      const name = fn.split("::").slice(1).join("::");
      counts.set(name, (counts.get(name) ?? 0) + 1);
      const out = view(name, args ?? []);
      return out ? send(200, out) : send(400, { message: "Move abort" });
    }
    send(404, { message: "no route" });
  }, LATENCY));
});

// ---------- gieo dữ liệu ----------
function account(role) {
  const priv = ed25519.utils.randomPrivateKey(), pub = ed25519.getPublicKey(priv);
  const address = hex(sha3_256(new Uint8Array([...pub, 0])));
  return { priv, pub: hex(pub), address, did: `did:vnu:${role}:${address}`, role,
    sign: (m) => hex(ed25519.sign(new TextEncoder().encode(m), priv)) };
}
async function enroll(base, a) {
  await call(base, "POST", "/entities/register", { address: a.address, publicKeyHex: a.pub, did: a.did, role: a.role, label: "Đo " + a.role });
  return login(base, a);
}
async function login(base, a) {
  const ch = await call(base, "POST", "/auth/challenge", { address: a.address });
  const vf = await call(base, "POST", "/auth/verify", { address: a.address, nonce: ch.data.data.nonce, signature: a.sign(ch.data.data.message) });
  return vf.data.data.token;
}
async function seed(base) {
  const fakeTx = () => "0x" + createHash("sha256").update(randomUUID()).digest("hex");
  const admin = account("admin"), issuer = account("issuer"), holder = account("holder"), deleg = account("issuer");
  for (const a of [admin, issuer, holder, deleg]) {
    a.token = await enroll(base, a);
    const doc = { "@context": ["https://www.w3.org/ns/did/v1"], id: a.did };
    const pin = await call(base, "POST", "/ipfs/pin", { json: doc, name: "d" }, a.token);
    await call(base, "POST", "/did/save", { did: a.did, documentCid: pin.data.data.cid, documentHash: sha3(doc), docJson: doc, txHash: fakeTx() }, a.token);
  }
  const vcs = [];
  for (let i = 0; i < N_VC; i++) {
    const vcId = `urn:uuid:${randomUUID()}`, id = 5000 + i;
    const vc = { id: vcId, issuer: issuer.did, credentialSubject: { id: holder.did, "vnu:degreeName": `Văn bằng ${i}` } };
    const env = { v: 1, alg: "A256GCM", aad: `vnu-vc:${sha3(vcId)}`, iv: b64(12), ct: b64(96),
      recipients: [{ kid: holder.address, role: "holder", epk: b64(32), iv: b64(12), wk: b64(48) }, { kid: issuer.address, role: "issuer", epk: b64(32), iv: b64(12), wk: b64(48) }] };
    const pin = await call(base, "POST", "/ipfs/pin", { json: env, name: "vc" }, issuer.token);
    const r = await call(base, "POST", "/issuer/credentials", { vcId, onChainVcId: id, holderDid: holder.did, holderAddress: holder.address,
      vcType: 1, ipfsCid: pin.data.data.cid, vcIdHash: sha3(vcId), contentHash: sha3(vc), proofValue: issuer.sign(canon(vc)),
      issuedAt: new Date().toISOString(), expiresAt: null, txHash: fakeTx() }, issuer.token);
    if (r.status !== 201) throw new Error("gieo VC: " + JSON.stringify(r.data));
    vcs.push({ vcId, vc, id });
    world.vcs.set(String(id), sha3(vc));
  }
  const vp = { type: ["VerifiablePresentation"], holder: holder.did, verifiableCredential: vcs.slice(0, K_VP).map((x) => x.vc) };
  const blob = await call(base, "POST", "/ipfs/pin", { json: { v: 1, alg: "A256GCM", iv: b64(12), ct: b64(96) }, name: "vp" }, holder.token);
  const pres = await call(base, "POST", "/holder/presentations", { vpId: `urn:uuid:${randomUUID()}`, vcIds: vcs.slice(0, K_VP).map((x) => x.vcId),
    ipfsCid: blob.data.data.cid, vpHash: sha3(vp), proofValue: holder.sign(canon(vp)), ttlSeconds: 86400 }, holder.token);
  if (pres.status !== 201) throw new Error("gieo VP: " + JSON.stringify(pres.data));
  // Sub-issuer của deleg: delegationSnapshot đọc danh sách từ nhật ký của chính nó.
  const subs = [];
  for (let i = 0; i < N_SUB; i++) {
    const s = account("issuer");
    await enroll(base, s);
    subs.push(s.address);
    psql(`INSERT INTO audit_log (actor, action, target, detail) VALUES ('${deleg.address}', 'authority.approve_issuer', '${s.address}', '{"byDelegation": true}')`, DB);
  }
  world = { admins: new Set([norm(admin.address)]), issuers: new Set([norm(issuer.address), norm(deleg.address)]),
    delegator: norm(deleg.address), subs: new Set(subs.map(norm)), vcs: world.vcs };
  return { admin, issuer, holder, deleg, vp, token: pres.data.data.share.token };
}

// ---------- đo ----------
const pct = (a, p) => a[Math.min(a.length - 1, Math.floor((a.length * p) / 100))];
async function measure(side, base, s) {
  const tokens = { admin: await login(base, s.admin), holder: await login(base, s.holder), deleg: await login(base, s.deleg) };
  const routes = [
    ["GET /holder/credentials (20 VC)", "GET", "/holder/credentials", null, tokens.holder],
    ["POST /verify/share (k=8)", "POST", `/verify/share/${s.token}`, { vp: s.vp }, null],
    ["GET /auth/me (admin)", "GET", "/auth/me", null, tokens.admin],
    ["GET /admin/audit", "GET", "/admin/audit", null, tokens.admin],
    ["GET /issuer/delegation (10 sub-issuer)", "GET", "/issuer/delegation", null, tokens.deleg],
  ];
  const rows = [];
  for (const [name, m, p, body, tok] of routes) {
    counts.clear();
    const first = await call(base, m, p, body, tok);
    const views = [...counts.values()].reduce((a, b) => a + b, 0);
    const detail = Object.fromEntries([...counts.entries()].sort((a, b) => b[1] - a[1]));
    const lat = [];
    for (let i = 0; i < N_REQ; i++) { const t0 = performance.now(); await call(base, m, p, body, tok); lat.push(performance.now() - t0); }
    lat.sort((a, b) => a - b);
    rows.push({ side, route: name, status: first.status, views, detail, p50: +pct(lat, 50).toFixed(1), p95: +pct(lat, 95).toFixed(1) });
    console.log(`  ${side.padEnd(3)} ${name.padEnd(40)} HTTP ${first.status}  view/yêu cầu ${String(views).padStart(3)}  p50 ${pct(lat, 50).toFixed(1)} ms  p95 ${pct(lat, 95).toFixed(1)} ms  ${JSON.stringify(detail)}`);
  }
  return rows;
}

try {
  await new Promise((ok) => mock.listen(4099, "127.0.0.1", ok));
  psql(`DROP DATABASE IF EXISTS ${DB} WITH (FORCE)`); psql(`CREATE DATABASE ${DB}`);
  execFileSync("bash", ["-c", `docker exec -i vnu_trust_postgres psql -q -U vnu_trust -d ${DB} < '${ROOT}db/schema.sql'`]);
  console.log(`== Gieo dữ liệu (offline) — ${N_VC} VC, VP k=${K_VP}, ${N_SUB} sub-issuer`);
  const off = start("TS", 4010, { VERIFY_ONCHAIN: "false" });
  await waitUp(4010);
  const s = await seed("http://localhost:4010/api");
  stop(off);
  console.log(`== Đo ở chế độ nghiêm ngặt, fullnode giả trễ ${LATENCY} ms/lần gọi, ${N_REQ} yêu cầu tuần tự mỗi tuyến`);
  const strict = { VERIFY_ONCHAIN: "true", CHAIN_FULLNODE: "http://localhost:4099/v1" };
  start("TS", 4095, strict); start("Go", 4096, strict);
  await waitUp(4095); await waitUp(4096);
  const rows = [...await measure("TS", "http://localhost:4095/api", s), ...await measure("Go", "http://localhost:4096/api", s)];
  writeFileSync(OUT, JSON.stringify({ at: new Date().toISOString(), latencyMs: LATENCY, nReq: N_REQ, rows }, null, 2));
  console.log(`\nĐã ghi ${OUT}`);
} finally {
  procs.forEach(stop);
  mock.close();
  try { psql(`DROP DATABASE IF EXISTS ${DB} WITH (FORCE)`); } catch { /* đã xoá */ }
}
