/**
 * M2 — Đọc chuỗi theo lô trên fullnode thật (CHỈ ĐỌC, không giao dịch).
 * 40 lượt, mỗi lượt 3 view nối tiếp: did_registry::resolve_did_by_owner, vc_registry::get_vcs_paginated,
 * authority::is_active_issuer. Đối số là địa chỉ gói (dữ liệu công khai). Nghỉ >= 300 ms giữa các lượt.
 * Tuỳ chọn: DID_ADDR=<địa chỉ ví thử> đo thêm 20 lượt resolve_did cho DID đó.
 *   node scripts/eval/chain-batch.mjs
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = process.env.ROOT ?? join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const env = Object.fromEntries(readFileSync(join(root, "chain.env"), "utf8").split("\n")
  .filter((l) => l.includes("=") && !l.trimStart().startsWith("#"))
  .map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim()]));
const FULLNODE = env.CHAIN_FULLNODE, C = env.CONTRACT_ADDRESS;
const OUT = process.env.OUT_DIR ?? join(root, ".bench", "eval-ts");
const N = Number(process.env.SAMPLES ?? 40), REST = Number(process.env.REST_MS ?? 1000);
mkdirSync(OUT, { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const pct = (a, p) => { const s = [...a].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)]; };
const stat = (a) => a.length ? { n: a.length, p50: pct(a, 50), p95: pct(a, 95), min: Math.min(...a), max: Math.max(...a) } : null;

let throttled = 0;
async function view(fn, args) {
  const t0 = performance.now();
  let status = 0, body = null;
  try {
    const r = await fetch(`${FULLNODE}/view`, { method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ function: `${C}::${fn}`, type_arguments: [], arguments: args }) });
    status = r.status; const t = await r.text(); try { body = JSON.parse(t); } catch { body = t; }
    if (status === 429) throttled++;
  } catch (e) { body = String(e); }
  return { ms: performance.now() - t0, status, ok: status === 200, body };
}

const rows = [];
const abort = [];
await view("authority::is_active_issuer", [C]); // khởi động kết nối, bỏ kết quả
for (let i = 0; i < N; i++) {
  const t0 = performance.now();
  const a = await view("did_registry::resolve_did_by_owner", [C]);
  const b = await view("vc_registry::get_vcs_paginated", ["0", "8"]);
  const c = await view("authority::is_active_issuer", [C]);
  rows.push({ resolve: a.ms, vcs: b.ms, issuer: c.ms, total: performance.now() - t0, status: [a.status, b.status, c.status] });
  if (i === 0) abort.push({ resolve: a.ok ? "ok" : String(JSON.stringify(a.body)).slice(0, 160), vcs: b.ok ? `ok (${Array.isArray(b.body?.[0]) ? b.body[0].length : "?"} bản ghi)` : String(JSON.stringify(b.body)).slice(0, 160), issuer: JSON.stringify(c.body) });
  await sleep(REST);
}
// resolve_did_by_owner trên địa chỉ gói abort (chưa có DID) = HTTP 400 do VM, vẫn là một vòng gọi hợp lệ để đo thời gian.
const okRows = rows.filter((r) => [200, 400].includes(r.status[0]) && r.status[1] === 200 && r.status[2] === 200);
const errors = rows.length - okRows.length;
const out = { meta: { at: new Date().toISOString(), fullnode: FULLNODE, contract: C, samples: N, restSleepMs: REST, mau: abort[0] },
  throttled429: throttled, loiLuot: errors,
  total: stat(okRows.map((r) => r.total)), resolve_did_by_owner: stat(okRows.map((r) => r.resolve)),
  get_vcs_paginated: stat(okRows.map((r) => r.vcs)), is_active_issuer: stat(okRows.map((r) => r.issuer)), raw: rows };

if (process.env.DID_ADDR) {
  const d = [], st = [];
  await sleep(500);
  for (let i = 0; i < 20; i++) { const r = await view("did_registry::resolve_did_by_owner", [process.env.DID_ADDR]); st.push(r.status); if (r.ok) d.push(r.ms); await sleep(350); }
  out.resolve_ví_thử = { addr: process.env.DID_ADDR, ...stat(d), statuses: st, raw: d };
}
writeFileSync(`${OUT}/chain-batch.json`, JSON.stringify(out, null, 2));
console.log(JSON.stringify({ throttled429: throttled, loiLuot: errors, mau: abort[0], total: out.total, resolve: out.resolve_did_by_owner, vcs: out.get_vcs_paginated, issuer: out.is_active_issuer }, null, 1));
