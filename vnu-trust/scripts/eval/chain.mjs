/**
 * Thí nghiệm F — chi phí phía chuỗi thật: độ trễ view function và gas qua mô phỏng.
 *
 * KHÔNG ghi gì lên chuỗi: chỉ gọi /view (đọc) và /transactions/simulate (chữ ký
 * toàn số 0 kèm khoá công khai thật — fullnode chạy giao dịch nhưng không lưu).
 *
 * Ba câu hỏi:
 *   1. Một vòng gọi view tới fullnode tốn bao lâu, nhìn từ máy chạy backend?
 *   2. Bản trình bày k văn bằng: mẫu gọi hiện tại (bước 5 tuần tự, k + 3 vòng nối
 *      tiếp) so với mẫu song song hoá (2 vòng) — chênh bao nhiêu khi đo thật?
 *   3. Một thao tác ghi tốn bao nhiêu gas?
 *
 *   node scripts/eval/chain.mjs
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { sha3_256 } from "@noble/hashes/sha3";

const root = process.env.ROOT ?? join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const env = Object.fromEntries(readFileSync(join(root, "chain.env"), "utf8").split("\n")
  .filter((l) => l.includes("=") && !l.trimStart().startsWith("#"))
  .map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim()]));
const FULLNODE = env.CHAIN_FULLNODE, C = env.CONTRACT_ADDRESS;
const OUT = process.env.OUT_DIR ?? "./.bench/eval";
const SAMPLES = Number(process.env.SAMPLES ?? 40);

const hex = (b) => "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const median = (a) => { const s = [...a].sort((x, y) => x - y); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const pct = (a, p) => { const s = [...a].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)]; };

let throttled = 0;
async function req(path, body) {
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const r = await fetch(FULLNODE + path, body ? { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) } : undefined);
      const t = await r.text();
      let b = null; try { b = t ? JSON.parse(t) : null; } catch { b = t; }
      if (r.status === 429 || (typeof b === "string" && /rate limited/i.test(b))) throttled++;
      return { status: r.status, body: b };
    } catch (e) { if (attempt === 2) throw e; await sleep(1000); }
  }
}
const view = (fn, args) => req("/view", { function: `${C}::${fn}`, type_arguments: [], arguments: args });
const randAddr = () => hex(sha3_256(new TextEncoder().encode(String(Math.random()))));
async function timed(fn) { const t0 = performance.now(); const r = await fn(); return { ms: performance.now() - t0, r }; }

// PARTS=rtt,pattern,gas — chạy riêng từng phần; kết quả gộp vào chain.json đã có.
const PARTS = new Set((process.env.PARTS ?? "rtt,pattern,gas").split(","));
const prev = existsSync(`${OUT}/chain.json`) ? JSON.parse(readFileSync(`${OUT}/chain.json`, "utf8")) : null;
const out = { meta: { ...(prev?.meta ?? {}), at: new Date().toISOString(), fullnode: FULLNODE, contract: C, samples: SAMPLES }, data: { ...(prev?.data ?? {}) } };
const log = (...x) => console.log("  ", ...x);

// ---- 1. Độ trễ một vòng gọi
if (PARTS.has("rtt")) {
  const ledger = [], v = [];
  await req("/"); await view("authority::get_root_admin", []);
  for (let i = 0; i < SAMPLES; i++) {
    ledger.push((await timed(() => req("/"))).ms);
    v.push((await timed(() => view("authority::is_active_issuer", [randAddr()]))).ms);
    await sleep(150);
  }
  out.data.rtt = { throttled, ledger: { p50: median(ledger), p95: pct(ledger, 95), min: Math.min(...ledger), max: Math.max(...ledger), raw: ledger },
    view: { p50: median(v), p95: pct(v, 95), min: Math.min(...v), max: Math.max(...v), raw: v } };
  log(`GET /: p50 ${median(ledger).toFixed(0)} ms · view: p50 ${median(v).toFixed(0)} ms, p95 ${pct(v, 95).toFixed(0)} ms`);
}

// ---- 2. Mẫu gọi của bước xác minh với k văn bằng
//   hiện tại: resolve_did → k × get_vc_status nối tiếp → k song song (toàn vẹn) → k song song (issuer)
//   song song hoá: resolve_did → mọi lời gọi còn lại cùng một lượt
if (PARTS.has("pattern")) {
  const one = () => view("authority::is_active_issuer", [randAddr()]);
  const all = (n) => Promise.all(Array.from({ length: n }, one));
  out.data.pattern = [];
  for (const k of [1, 2, 4, 8]) {
    const seq = [], par = [];
    const before = throttled;
    for (let r = 0; r < 5; r++) {
      seq.push((await timed(async () => { await one(); for (let i = 0; i < k; i++) await one(); await all(k); await all(k); })).ms);
      await sleep(1500);
      par.push((await timed(async () => { await one(); await all(3 * k); })).ms);
      await sleep(1500);
    }
    out.data.pattern.push({ k, throttled: throttled - before, calls: 5 * 2 * (1 + 3 * k), sequential: { p50: median(seq), min: Math.min(...seq), max: Math.max(...seq) }, parallel: { p50: median(par), min: Math.min(...par), max: Math.max(...par) } });
    log(`k=${k}: tuần tự ${median(seq).toFixed(0)} ms, song song ${median(par).toFixed(0)} ms, bị chặn ${throttled - before}`);
  }
}

// ---- 3. Gas qua mô phỏng (người gửi là địa chỉ đã publish gói = root hiện tại)
if (PARTS.has("gas")) {
  const PUB = "0x61ce325bb8fe57aa698412bfbe7b4ebc1f9c7673f44eae46d5595f7037679229";
  const pubBytes = new Uint8Array(PUB.slice(2).match(/../g).map((x) => parseInt(x, 16)));
  const SENDER = hex(sha3_256(new Uint8Array([...pubBytes, 0x00])));
  const acct = await req(`/accounts/${SENDER}`);
  const normA = (a) => "0x" + String(a ?? "").replace(/^0x/, "").padStart(64, "0");
  const rootAdmin = normA((await view("authority::get_root_admin", [])).body?.[0]);
  const bytesArg = (s) => hex(new TextEncoder().encode(s));
  const docHash = hex(sha3_256(new TextEncoder().encode("{}")));
  const cid = "bafkreiabcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqr";
  const sim = async (fn, args) => {
    const tx = { sender: SENDER, sequence_number: acct.body.sequence_number, max_gas_amount: "200000", gas_unit_price: "100",
      expiration_timestamp_secs: String(Math.floor(Date.now() / 1000) + 120),
      payload: { type: "entry_function_payload", function: `${C}::${fn}`, type_arguments: [], arguments: args } };
    const r = await req("/transactions/simulate?estimate_gas_unit_price=true", { ...tx, signature: { type: "ed25519_signature", public_key: PUB, signature: "0x" + "0".repeat(128) } });
    const x = Array.isArray(r.body) ? r.body[0] : r.body;
    return { fn, vmStatus: x?.vm_status, success: x?.success, gasUsed: Number(x?.gas_used), gasUnitPrice: Number(x?.gas_unit_price) };
  };
  out.data.gas = { sender: SENDER, rootAdmin, senderIsRoot: rootAdmin === SENDER, ops: [] };
  out.data.gas.ops.push(await sim("did_registry::register_did", [bytesArg(`did:vnu:root:${SENDER}`), bytesArg(cid), docHash]));
  if (rootAdmin === SENDER) out.data.gas.ops.push(await sim("authority::propose_root", [randAddr()]));
  for (const o of out.data.gas.ops) log(`${o.fn}: ${o.vmStatus} · gas ${o.gasUsed} × ${o.gasUnitPrice} octa`);
}

mkdirSync(OUT, { recursive: true });
writeFileSync(`${OUT}/chain.json`, JSON.stringify(out, null, 2));
console.log(`  → ${OUT}/chain.json`);
