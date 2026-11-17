/**
 * M3 — Độ trễ GHI trên testnet, dựng giao dịch KHÔNG dùng Aptos SDK, đúng đường của chain.ts:
 *   POST /transactions/encode_submission -> ký @noble -> POST /transactions -> poll by_hash mỗi 100 ms.
 *
 * Giới hạn: chỉ ví thử sinh MỚI trong bộ nhớ (không đọc khoá có sẵn, không ghi khoá xuống đĩa);
 * chỉ gọi did_registry::{register_did, update_did_document, suspend_own_did, reactivate_own_did};
 * không chuyển token; faucet chỉ cho ví thử (tối đa 6 lần); tổng giao dịch ghi <= 40.
 *
 * Chạy từ frontend/ (cần @noble/*):  node write-latency.mjs
 */
import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";
import { sha256 } from "@noble/hashes/sha256";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = process.env.ROOT ?? join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const env = Object.fromEntries(readFileSync(join(root, "chain.env"), "utf8").split("\n")
  .filter((l) => l.includes("=") && !l.trimStart().startsWith("#"))
  .map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim()]));
const FULLNODE = env.CHAIN_FULLNODE, C = env.CONTRACT_ADDRESS, FAUCET = env.CHAIN_FAUCET;
const OUT = process.env.OUT_DIR ?? join(root, ".bench", "eval-ts");
mkdirSync(OUT, { recursive: true });

const MAX_TX = 40, MAX_FAUCET = 6, MAX_GAS = "200000", EXPIRY = 120;
const hex = (b) => "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const fromHex = (h) => new Uint8Array(h.replace(/^0x/, "").match(/../g).map((x) => parseInt(x, 16)));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = () => performance.now();
const bytesArg = (s) => hex(new TextEncoder().encode(s));
const canon = (v) => v === null || typeof v !== "object" ? JSON.stringify(v)
  : Array.isArray(v) ? "[" + v.map(canon).join(",") + "]"
  : "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
const med = (a) => { if (!a.length) return null; const s = [...a].sort((x, y) => x - y); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const pct = (a, p) => { const s = [...a].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)]; };

// CIDv1 raw (0x55) + sha2-256 (0x12 0x20), base32 chữ thường không đệm, tiền tố "b"
const B32 = "abcdefghijklmnopqrstuvwxyz234567";
function cidOf(bytes) {
  const b = new Uint8Array([0x01, 0x55, 0x12, 0x20, ...sha256(bytes)]);
  let bits = 0, val = 0, out = "";
  for (const x of b) { val = (val << 8) | x; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return "b" + out;
}

async function node(path, init) {
  const r = await fetch(FULLNODE + path, init);
  const t = await r.text(); let b; try { b = t ? JSON.parse(t) : null; } catch { b = t; }
  return { status: r.status, body: b };
}
const post = (path, body) => node(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });

const wallets = Array.from({ length: 4 }, () => {
  const priv = ed25519.utils.randomPrivateKey(); const pub = ed25519.getPublicKey(priv);
  return { priv, pubHex: hex(pub), address: hex(sha3_256(new Uint8Array([...pub, 0x00]))), version: 1 };
});
for (const w of wallets) w.did = `did:vnu:holder:${w.address}`;

let faucetCalls = 0, txCount = 0;
const raw = [];
const log = (...x) => console.log("  ", ...x);

async function balance(addr) {
  const r = await node(`/accounts/${addr}/resource/0x1::coin::CoinStore%3C0x1::aptos_coin::AptosCoin%3E`);
  return r.status === 200 ? BigInt(r.body.data.coin.value) : 0n;
}
async function fund(w) {
  if (faucetCalls >= MAX_FAUCET) throw new Error("hết lượt faucet");
  faucetCalls++;
  const r = await fetch(`${FAUCET}/mint?amount=100000000&address=${w.address}`, { method: "POST" });
  if (!r.ok) throw new Error(`faucet ${r.status}`);
  for (let i = 0; i < 60; i++) { if ((await balance(w.address)) > 0n) return; await sleep(1000); }
  throw new Error("số dư không lên sau faucet");
}
async function seqOf(addr) {
  const r = await node(`/accounts/${addr}`);
  return r.status === 200 ? r.body.sequence_number : "0";
}
let gasPrice = null;
async function price() { if (!gasPrice) { const r = await node("/estimate_gas_price"); gasPrice = String(r.body?.gas_estimate || 100); } return gasPrice; }

function docFor(w, n) {
  const doc = { "@context": ["https://www.w3.org/ns/did/v1"], id: w.did,
    verificationMethod: [{ id: `${w.did}#key-1`, type: "Ed25519VerificationKey2020", controller: w.did, publicKeyMultibase: w.pubHex }],
    authentication: [`${w.did}#key-1`], service: [{ id: `${w.did}#svc-${n}`, type: "LinkedDomains", serviceEndpoint: `https://example.edu.vn/${n}` }] };
  const text = canon(doc);
  return { cid: cidOf(new TextEncoder().encode(text)), hash: hex(sha3_256(new TextEncoder().encode(text))) };
}

/** Một giao dịch ghi đầy đủ. Trả bản ghi đo. */
async function send(w, fn, args, label) {
  if (txCount >= MAX_TX) throw new Error("vượt trần số giao dịch");
  txCount++;
  const t0 = now();
  const sequence = await seqOf(w.address); const gp = await price();
  const tPrep = now() - t0;
  const tx = { sender: w.address, sequence_number: sequence, max_gas_amount: MAX_GAS, gas_unit_price: gp,
    expiration_timestamp_secs: String(Math.floor(Date.now() / 1000) + EXPIRY),
    payload: { type: "entry_function_payload", function: `${C}::${fn}`, type_arguments: [], arguments: args } };
  const e0 = now();
  const enc = await post("/transactions/encode_submission", tx);
  const tEncode = now() - e0;
  if (enc.status !== 200) return { fn, label, error: `encode ${enc.status} ${JSON.stringify(enc.body).slice(0, 200)}`, success: false };
  const sig = ed25519.sign(fromHex(enc.body), w.priv);
  const s0 = now();
  const sub = await post("/transactions", { ...tx, signature: { type: "ed25519_signature", public_key: w.pubHex, signature: hex(sig) } });
  const tSubmit = now() - s0;
  if (sub.status >= 300) return { fn, label, error: `submit ${sub.status} ${JSON.stringify(sub.body).slice(0, 200)}`, success: false };
  const hash = sub.body.hash;
  const c0 = now(); let polls = 0, res = null;
  while (now() - c0 < 60000) {
    polls++;
    const r = await node(`/transactions/by_hash/${hash}`);
    if (r.status === 200 && r.body.type !== "pending_transaction") { res = r.body; break; }
    await sleep(100);
  }
  const tConfirm = now() - c0, tTotal = now() - t0;
  if (!res) return { fn, label, hash, error: "quá hạn chờ xác nhận", success: false, t_confirm: tConfirm, t_total: tTotal, polls };
  return { fn, label, hash, version: res.version, success: res.success === true, vm_status: res.vm_status, gas_used: Number(res.gas_used),
    gas_unit_price: Number(res.gas_unit_price), timestamp_us: res.timestamp, t_prep: tPrep, t_encode: tEncode, t_submit: tSubmit,
    t_confirm: tConfirm, t_total: tTotal, polls };
}
async function record(w, fn, args, label) {
  let r = await send(w, fn, args, label);
  log(`${label}: ${r.success ? "OK" : "LỖI"} ${r.hash?.slice(0, 12) ?? ""} total ${r.t_total?.toFixed(0)} ms ${r.error ?? r.vm_status ?? ""}`);
  if (!r.success) { raw.push({ ...r, attempt: 1 }); await sleep(1000); r = await send(w, fn, args, label); r.attempt = 2;
    log(`  thử lại: ${r.success ? "OK" : "LỖI"} ${r.error ?? r.vm_status ?? ""}`); }
  else r.attempt = 1;
  raw.push({ ...r, wallet: w.address });
  await sleep(1000);
  return r;
}

// ---------------- chạy
log(`ví thử: ${wallets.map((w) => w.address.slice(0, 12)).join(" ")}`);
await fund(wallets[0]);
log(`faucet 1/${MAX_FAUCET}, số dư ${await balance(wallets[0].address)}`);

// Mô phỏng MỘT register_did trước khi gửi thật
{
  const w = wallets[0]; const d = docFor(w, 0);
  const args = [bytesArg(w.did), bytesArg(d.cid), d.hash];
  const tx = { sender: w.address, sequence_number: await seqOf(w.address), max_gas_amount: MAX_GAS, gas_unit_price: await price(),
    expiration_timestamp_secs: String(Math.floor(Date.now() / 1000) + EXPIRY),
    payload: { type: "entry_function_payload", function: `${C}::did_registry::register_did`, type_arguments: [], arguments: args } };
  const sim = await post("/transactions/simulate", { ...tx, signature: { type: "ed25519_signature", public_key: w.pubHex, signature: "0x" + "0".repeat(128) } });
  const x = Array.isArray(sim.body) ? sim.body[0] : sim.body;
  log(`mô phỏng register_did: ${x?.vm_status} gas ${x?.gas_used}`);
  if (sim.status !== 200 || x?.success !== true) { console.error("mô phỏng hỏng, DỪNG:", JSON.stringify(sim.body).slice(0, 300)); process.exit(1); }
  var simResult = { vm_status: x.vm_status, gas_used: Number(x.gas_used), gas_unit_price: Number(x.gas_unit_price) };
}

for (let i = 0; i < wallets.length; i++) {
  const w = wallets[i];
  if (i > 0) { await fund(w); log(`faucet ${faucetCalls}/${MAX_FAUCET}`); }
  const d = docFor(w, 0);
  await record(w, "did_registry::register_did", [bytesArg(w.did), bytesArg(d.cid), d.hash], `register_did #${i + 1}`);
}
const W = wallets[0];
for (let i = 1; i <= 10; i++) {
  const d = docFor(W, i);
  const r = await record(W, "did_registry::update_did_document", [bytesArg(d.cid), d.hash, String(W.version)], `update_did_document #${i}`);
  if (r.success) W.version++;
}
for (let i = 1; i <= 6; i++) {
  await record(W, "did_registry::suspend_own_did", [], `suspend_own_did #${i}`);
  await record(W, "did_registry::reactivate_own_did", [], `reactivate_own_did #${i}`);
}

// ---------------- tóm tắt
const byFn = {};
for (const r of raw.filter((x) => x.success)) (byFn[r.fn] ??= []).push(r);
const summary = {};
for (const [fn, rs] of Object.entries(byFn)) {
  const T = rs.map((r) => r.t_total), F = rs.map((r) => r.t_confirm);
  summary[fn] = { n: rs.length,
    t_total: { p50: med(T), p95: pct(T, 95), min: Math.min(...T), max: Math.max(...T) },
    t_confirm: { p50: med(F), p95: pct(F, 95), min: Math.min(...F), max: Math.max(...F) },
    gas_used_median: med(rs.map((r) => r.gas_used)), gas_unit_price_median: med(rs.map((r) => r.gas_unit_price)) };
}
const out = { meta: { at: new Date().toISOString(), fullnode: FULLNODE, contract: C, wallets: wallets.map((w) => w.address), faucetCalls, txSent: txCount,
    simulate: simResult, pollIntervalMs: 100, restBetweenTxMs: 1000 },
  summary, raw };
writeFileSync(`${OUT}/write-latency.json`, JSON.stringify(out, null, 2));
console.log(JSON.stringify({ txSent: txCount, ok: raw.filter((r) => r.success).length, faucetCalls, summary }, null, 1));
console.log(`  → ${OUT}/write-latency.json`);
