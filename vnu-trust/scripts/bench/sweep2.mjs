/**
 * Quét mức đồng thời, LẶP LẠI nhiều lượt mỗi điểm rồi lấy trung vị.
 *
 * Lượt quét đầu (trong `bench/sweep.mjs`) đo một lượt cho mỗi điểm, và kết quả
 * không đơn điệu: thông lượng của `/health` ở cài đặt TypeScript đi
 * 741 → 1471 → 2339 → 2731 → 1647 → 3851 → 3360 yc/s. Mức giảm ở c=16 không
 * phản ánh hành vi hệ thống mà phản ánh chính nhiễu đo mà thí nghiệm số mẫu
 * đã lượng hoá được.
 *
 * Bản này sửa hai điều: mỗi điểm lặp REPEATS lượt và báo TRUNG VỊ (bền với
 * giá trị ngoại lai hơn trung bình), và số mẫu mỗi lượt tối thiểu 1000 thay vì
 * 240 — mức mà thí nghiệm số mẫu cho thấy độ phân tán bắt đầu giảm rõ.
 *
 *   node scripts/bench/sweep2.mjs
 */
import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";
import { writeFileSync, mkdirSync } from "node:fs";

const TS = process.env.TS_BASE ?? "http://localhost:4000/api";
const GO = process.env.GO_BASE ?? "http://localhost:4001/api";
const OUT = process.env.OUT_DIR ?? "./.bench";
const REPEATS = Number(process.env.REPEATS ?? 5);
const SWEEP = (process.env.SWEEP ?? "1,2,4,8,16,32,64").split(",").map(Number);

const hex = (b) => "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const pct = (s, p) => s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)];
const median = (a) => {
  const s = [...a].sort((x, y) => x - y);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};

async function call(base, path, token) {
  const r = await fetch(base + path, { headers: token ? { authorization: "Bearer " + token } : {} });
  await r.text();
  return r.status;
}

async function bench(fn, total, conc) {
  const lat = [];
  let next = 0, bad = 0, throttled = 0;
  const t0 = performance.now();
  await Promise.all(
    Array.from({ length: conc }, async () => {
      while (next < total) {
        next += 1;
        const s = performance.now();
        try {
          const c = await fn();
          if (c === 429) throttled += 1;
          else if (c >= 400) bad += 1;
        } catch { bad += 1; }
        lat.push(performance.now() - s);
      }
    }),
  );
  const wall = performance.now() - t0;
  const sorted = lat.sort((a, b) => a - b);
  return { rps: total / (wall / 1000), p50: pct(sorted, 50), p95: pct(sorted, 95), p99: pct(sorted, 99), bad, throttled };
}

async function register(base) {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  const address = hex(sha3_256(new Uint8Array([...pub, 0x00])));
  const did = `did:vnu:holder:${address}`;
  const post = (p, b, t) =>
    fetch(base + p, {
      method: "POST",
      headers: { "content-type": "application/json", ...(t ? { authorization: "Bearer " + t } : {}) },
      body: JSON.stringify(b),
    }).then((r) => r.json());
  await post("/entities/register", { address, publicKeyHex: hex(pub), did, role: "holder", label: "Quet dong thoi" });
  const ch = await post("/auth/challenge", { address });
  const vf = await post("/auth/verify", {
    address, nonce: ch.data.nonce,
    signature: hex(ed25519.sign(new TextEncoder().encode(ch.data.message), priv)),
  });
  return { did, token: vf.data.token, post };
}

async function seedDid(base) {
  const a = await register(base);
  const doc = { "@context": ["https://www.w3.org/ns/did/v1"], id: a.did };
  const pin = await a.post("/ipfs/pin", { json: doc, name: "sw2" }, a.token);
  const canon = (v) =>
    v === null || typeof v !== "object" ? JSON.stringify(v)
      : Array.isArray(v) ? "[" + v.map(canon).join(",") + "]"
        : "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
  const ok = await a.post("/did/save", {
    did: a.did, documentCid: pin.data.cid,
    documentHash: hex(sha3_256(new TextEncoder().encode(canon(doc)))),
    docJson: doc, txHash: "0x" + "cd".repeat(32),
  }, a.token);
  return ok?.success ? a.did : null;
}

console.log("Chuẩn bị…");
const accTS = await register(TS);
const accGO = await register(GO);
const probeDid = await seedDid(TS);
if (!probeDid) { console.error("Không tạo được DID mẫu."); process.exit(1); }

const ROUTES = {
  "/health": (b, t) => () => call(b, "/health"),
  "/did/resolve": (b, t) => () => call(b, "/did/resolve?did=" + encodeURIComponent(probeDid)),
  "/auth/me": (b, t) => () => call(b, "/auth/me", t),
};
const BACKENDS = [["TS", TS, accTS.token], ["GO", GO, accGO.token]];

console.log("Làm nóng…");
for (const [, b, t] of BACKENDS) {
  for (const mk of Object.values(ROUTES)) await bench(mk(b, t), 600, 12);
}

console.log(`\nQuét ${SWEEP.join(", ")} | ${REPEATS} lượt mỗi điểm | n = max(1000, 40c)\n`);
const data = [];
let totalReq = 0;
for (const [tag, base, tok] of BACKENDS) {
  for (const [route, mk] of Object.entries(ROUTES)) {
    const line = [];
    for (const conc of SWEEP) {
      const n = Math.max(1000, conc * 40);
      const runs = [];
      for (let i = 0; i < REPEATS; i++) {
        runs.push(await bench(mk(base, tok), n, conc));
        totalReq += n;
        await sleep(120);
      }
      const row = {
        backend: tag, route, conc, n, repeats: REPEATS,
        rps: median(runs.map((r) => r.rps)),
        rps_min: Math.min(...runs.map((r) => r.rps)),
        rps_max: Math.max(...runs.map((r) => r.rps)),
        p50: median(runs.map((r) => r.p50)),
        p95: median(runs.map((r) => r.p95)),
        p95_min: Math.min(...runs.map((r) => r.p95)),
        p95_max: Math.max(...runs.map((r) => r.p95)),
        p99: median(runs.map((r) => r.p99)),
        bad: runs.reduce((s, r) => s + r.bad, 0),
        throttled: runs.reduce((s, r) => s + r.throttled, 0),
      };
      data.push(row);
      line.push(`c${conc}:${row.rps.toFixed(0)}`);
    }
    const rows = data.filter((x) => x.backend === tag && x.route === route);
    const peak = rows.reduce((a, b) => (b.rps > a.rps ? b : a));
    console.log(`  ${tag} ${route.padEnd(15)} ${line.join(" ")}`);
    console.log(`     đỉnh ${peak.rps.toFixed(0)} yc/s tại c=${peak.conc} (p95 ${peak.p95.toFixed(1)} ms)` +
      `  | p95 lớn nhất ${Math.max(...rows.map((x) => x.p95_max)).toFixed(1)} ms` +
      `  | lỗi ${rows.reduce((s, x) => s + x.bad, 0)}  429: ${rows.reduce((s, x) => s + x.throttled, 0)}`);
  }
}

mkdirSync(OUT, { recursive: true });
writeFileSync(`${OUT}/sweep2.json`, JSON.stringify({
  meta: { startedAt: new Date().toISOString(), repeats: REPEATS, sweep: SWEEP, probeDid, totalRequests: totalReq },
  data,
}, null, 2));
console.log(`\nXong. ${totalReq.toLocaleString("vi-VN")} yêu cầu. ${OUT}/sweep2.json`);
