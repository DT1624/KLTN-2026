/**
 * BỘ ĐO MỞ RỘNG — sinh dữ liệu thô để vẽ biểu đồ cho báo cáo.
 *
 * `perf.mjs` đo MỘT lượt ở MỘT mức đồng thời, nên nó trả lời được "hệ thống có
 * chậm không" mà không trả lời được ba câu hỏi mà một phép đo cần trả lời:
 *
 *   1. Số đo có lặp lại được không?      -> chạy lại N lần, xem độ phân tán
 *   2. Hệ thống bão hoà ở đâu?            -> quét mức đồng thời 1..64
 *   3. Vì sao báo p95 chứ không báo mean? -> giữ độ trễ từng yêu cầu, vẽ phân bố
 *
 * Kết quả ghi ra JSON để tách hẳn việc ĐO khỏi việc VẼ — vẽ lại biểu đồ không
 * cần đo lại, và dữ liệu thô vẫn kiểm chứng được.
 *
 *   node scripts/bench/sweep.mjs            # cả ba thí nghiệm
 *   REPEATS=20 node scripts/bench/sweep.mjs # đổi số lượt lặp
 */
import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";
import { writeFileSync, mkdirSync } from "node:fs";

const TS = process.env.TS_BASE ?? "http://localhost:4000/api";
const GO = process.env.GO_BASE ?? "http://localhost:4001/api";
const OUT = process.env.OUT_DIR ?? "./.bench";
const REPEATS = Number(process.env.REPEATS ?? 15);
const SWEEP = (process.env.SWEEP ?? "1,2,4,8,16,32,64").split(",").map(Number);

const hex = (b) => "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function call(base, method, path, body, token) {
  const r = await fetch(base + path, {
    method,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: "Bearer " + token } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  await r.text();
  return r.status;
}

/** Phân vị theo phương pháp nearest-rank trên mảng ĐÃ sắp xếp. */
const pct = (sorted, p) => sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)];
const mean = (a) => a.reduce((x, y) => x + y, 0) / a.length;
const sd = (a) => {
  if (a.length < 2) return 0;
  const m = mean(a);
  return Math.sqrt(a.reduce((s, x) => s + (x - m) ** 2, 0) / (a.length - 1));
};

/**
 * Chạy `total` yêu cầu với tối đa `conc` yêu cầu đồng thời.
 * Trả về CẢ mảng độ trễ thô, để bên gọi tự chọn thống kê cần dùng.
 */
async function bench(fn, { total, conc }) {
  const lat = [];
  const codes = {};
  let next = 0;
  const t0 = performance.now();
  await Promise.all(
    Array.from({ length: conc }, async () => {
      while (next < total) {
        next += 1;
        const s = performance.now();
        try {
          const code = await fn();
          codes[code] = (codes[code] ?? 0) + 1;
        } catch {
          codes.err = (codes.err ?? 0) + 1;
        }
        lat.push(performance.now() - s);
      }
    }),
  );
  const wall = performance.now() - t0;
  const sorted = [...lat].sort((a, b) => a - b);
  return {
    n: lat.length,
    rps: total / (wall / 1000),
    mean: mean(lat),
    p50: pct(sorted, 50),
    p95: pct(sorted, 95),
    p99: pct(sorted, 99),
    max: sorted[sorted.length - 1],
    codes,
    throttled: codes[429] ?? 0,
    errors: Object.entries(codes)
      .filter(([c]) => c === "err" || (Number(c) >= 400 && Number(c) !== 429))
      .reduce((n, [, v]) => n + v, 0),
    lat,
  };
}

// ---------- Chuẩn bị dữ liệu: tài khoản và một DID có thật để dò ----------

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

  await post("/entities/register", {
    address, publicKeyHex: hex(pub), did, role: "holder", label: "Do hieu nang mo rong",
  });
  const ch = await post("/auth/challenge", { address });
  const vf = await post("/auth/verify", {
    address, nonce: ch.data.nonce,
    signature: hex(ed25519.sign(new TextEncoder().encode(ch.data.message), priv)),
  });
  return { priv, pub, address, did, token: vf.data.token, post };
}

/** Đăng ký một DID có DID Document thật, để tuyến resolve phải làm việc. */
async function seedDid(base) {
  const a = await register(base);
  const doc = { "@context": ["https://www.w3.org/ns/did/v1"], id: a.did };
  const pin = await a.post("/ipfs/pin", { json: doc, name: "bench" }, a.token);
  const canon = (v) =>
    v === null || typeof v !== "object" ? JSON.stringify(v)
      : Array.isArray(v) ? "[" + v.map(canon).join(",") + "]"
        : "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
  const saved = await a.post("/did/save", {
    did: a.did, documentCid: pin.data.cid,
    documentHash: hex(sha3_256(new TextEncoder().encode(canon(doc)))),
    docJson: doc, txHash: "0x" + "cd".repeat(32),
  }, a.token);
  return saved?.success ? a.did : null;
}

console.log("Chuẩn bị dữ liệu…");
const accTS = await register(TS);
const accGO = await register(GO);
const probeDid = process.env.PROBE_DID ?? (await seedDid(TS));
if (!probeDid) {
  console.error("Không tạo được DID mẫu — phép đo cần VERIFY_ONCHAIN=false.");
  process.exit(1);
}
console.log(`  DID mẫu: ${probeDid.slice(0, 32)}…\n`);

const ROUTES = {
  "/health":              (b, t) => () => call(b, "GET", "/health"),
  "/stats":               (b, t) => () => call(b, "GET", "/stats"),
  "/did/resolve":         (b, t) => () => call(b, "GET", "/did/resolve?did=" + encodeURIComponent(probeDid)),
  "/lookup":              (b, t) => () => call(b, "GET", "/lookup?q=" + encodeURIComponent(probeDid)),
  "/auth/me":             (b, t) => () => call(b, "GET", "/auth/me", null, t),
  "/holder/credentials":  (b, t) => () => call(b, "GET", "/holder/credentials", null, t),
};
const BACKENDS = [["TS", TS, accTS.token], ["GO", GO, accGO.token]];

mkdirSync(OUT, { recursive: true });
const meta = {
  startedAt: new Date().toISOString(),
  node: process.version,
  repeats: REPEATS,
  sweep: SWEEP,
  probeDid,
};

/** Làm nóng để không đo lẫn chi phí biên dịch JIT và mở kết nối lần đầu. */
async function warmup() {
  for (const [, base, tok] of BACKENDS) {
    for (const mk of Object.values(ROUTES)) {
      await bench(mk(base, tok), { total: 30, conc: 4 });
    }
  }
}
console.log("Làm nóng…");
await warmup();

// ================= Thí nghiệm 1: độ lặp lại =================
// Cùng một phép đo, chạy REPEATS lần. Câu hỏi: p95 dao động bao nhiêu?
console.log(`\n[1/3] Độ lặp lại — ${REPEATS} lượt × 120 yêu cầu, đồng thời 12`);
const repeat = [];
for (const [tag, base, tok] of BACKENDS) {
  for (const [route, mk] of Object.entries(ROUTES)) {
    const runs = [];
    for (let i = 0; i < REPEATS; i++) {
      const r = await bench(mk(base, tok), { total: 120, conc: 12 });
      runs.push({ rps: r.rps, p50: r.p50, p95: r.p95, p99: r.p99, errors: r.errors, throttled: r.throttled });
      await sleep(150);
    }
    const p95s = runs.map((r) => r.p95);
    const rpss = runs.map((r) => r.rps);
    repeat.push({
      backend: tag, route, runs,
      p95_mean: mean(p95s), p95_sd: sd(p95s), p95_min: Math.min(...p95s), p95_max: Math.max(...p95s),
      rps_mean: mean(rpss), rps_sd: sd(rpss),
      errors: runs.reduce((n, r) => n + r.errors, 0),
      throttled: runs.reduce((n, r) => n + r.throttled, 0),
    });
    const last = repeat[repeat.length - 1];
    const cv = (last.p95_sd / last.p95_mean) * 100;
    console.log(
      `  ${tag} ${route.padEnd(21)} p95 ${last.p95_mean.toFixed(1)} ± ${last.p95_sd.toFixed(1)} ms` +
      ` (CV ${cv.toFixed(1)}%)  ${last.rps_mean.toFixed(0)} yc/s  lỗi ${last.errors}`,
    );
  }
}
writeFileSync(`${OUT}/repeat.json`, JSON.stringify({ meta, data: repeat }, null, 2));

// ================= Thí nghiệm 2: quét mức đồng thời =================
// Câu hỏi: thông lượng tăng đến mức đồng thời nào thì ngừng tăng, và p95 đổi thế nào?
console.log(`\n[2/3] Quét mức đồng thời — ${SWEEP.join(", ")}`);
const sweep = [];
for (const [tag, base, tok] of BACKENDS) {
  for (const [route, mk] of Object.entries(ROUTES)) {
    for (const conc of SWEEP) {
      const total = Math.max(240, conc * 20);
      const r = await bench(mk(base, tok), { total, conc });
      sweep.push({
        backend: tag, route, conc, total,
        rps: r.rps, mean: r.mean, p50: r.p50, p95: r.p95, p99: r.p99, max: r.max,
        errors: r.errors, throttled: r.throttled,
      });
      await sleep(120);
    }
    const rows = sweep.filter((x) => x.backend === tag && x.route === route);
    const best = rows.reduce((a, b) => (b.rps > a.rps ? b : a));
    console.log(
      `  ${tag} ${route.padEnd(21)} đỉnh ${best.rps.toFixed(0)} yc/s tại c=${best.conc}` +
      `  (p95 ${best.p95.toFixed(0)} ms)  lỗi ${rows.reduce((n, x) => n + x.errors, 0)}`,
    );
  }
}
writeFileSync(`${OUT}/sweep.json`, JSON.stringify({ meta, data: sweep }, null, 2));

// ================= Thí nghiệm 3: phân bố độ trễ =================
// Giữ lại độ trễ THÔ của một lượt lớn, để vẽ hàm phân bố tích luỹ.
// Mục đích: cho thấy vì sao mean che mất điều mà p95 chỉ ra.
console.log("\n[3/3] Phân bố độ trễ — 1500 yêu cầu mỗi tuyến, đồng thời 12");
const dist = [];
for (const [tag, base, tok] of BACKENDS) {
  for (const route of ["/health", "/stats", "/did/resolve"]) {
    const r = await bench(ROUTES[route](base, tok), { total: 1500, conc: 12 });
    const sorted = [...r.lat].sort((a, b) => a - b);
    dist.push({
      backend: tag, route, n: r.n,
      mean: r.mean, p50: r.p50, p75: pct(sorted, 75), p90: pct(sorted, 90),
      p95: r.p95, p99: r.p99, p999: pct(sorted, 99.9), max: r.max,
      errors: r.errors,
      // Lưu toàn bộ độ trễ, làm tròn tới 3 chữ số thập phân cho gọn tệp.
      lat: sorted.map((x) => Math.round(x * 1000) / 1000),
    });
    const d = dist[dist.length - 1];
    console.log(
      `  ${tag} ${route.padEnd(21)} mean ${d.mean.toFixed(1)}  p50 ${d.p50.toFixed(1)}` +
      `  p95 ${d.p95.toFixed(1)}  p99 ${d.p99.toFixed(1)}  max ${d.max.toFixed(1)} ms` +
      `  (p95/p50 = ${(d.p95 / d.p50).toFixed(1)}×)`,
    );
    await sleep(200);
  }
}
writeFileSync(`${OUT}/dist.json`, JSON.stringify({ meta, data: dist }, null, 2));

meta.finishedAt = new Date().toISOString();
writeFileSync(`${OUT}/meta.json`, JSON.stringify(meta, null, 2));
console.log(`\nXong. Dữ liệu thô: ${OUT}/{repeat,sweep,dist,meta}.json`);
