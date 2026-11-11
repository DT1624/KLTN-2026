/**
 * THÍ NGHIỆM: số mẫu bao nhiêu thì phép đo độ trễ mới lặp lại được?
 *
 * `perf.mjs` đo 120 yêu cầu mỗi tuyến. Thí nghiệm độ lặp lại ở
 * `bench/sweep.mjs` cho thấy p95 ở mức đó có hệ số biến thiên 45–205%, tức là
 * một con số đo một lượt gần như không nói lên điều gì. Có hai cách giải
 * thích, và chúng dẫn tới hai kết luận khác nhau:
 *
 *   (a) p95 bản chất đã dao động -> phải báo p95 kèm độ lệch chuẩn
 *   (b) 120 mẫu là quá ít        -> phải tăng số mẫu, p95 sẽ ổn định lại
 *
 * Phân biệt hai giả thuyết bằng cách giữ nguyên mức đồng thời và chỉ thay đổi
 * số mẫu, mỗi mức lặp lại nhiều lượt để đo chính độ phân tán.
 *
 *   node scripts/bench/samplesize.mjs
 */
import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";
import { writeFileSync, mkdirSync } from "node:fs";

const TS = process.env.TS_BASE ?? "http://localhost:4000/api";
const GO = process.env.GO_BASE ?? "http://localhost:4001/api";
const OUT = process.env.OUT_DIR ?? "./.bench";
const CONC = Number(process.env.CONC ?? 12);
const REPEATS = Number(process.env.REPEATS ?? 12);
const SIZES = (process.env.SIZES ?? "60,120,250,500,1000,2000,4000").split(",").map(Number);

const hex = (b) => "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const pct = (s, p) => s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)];
const mean = (a) => a.reduce((x, y) => x + y, 0) / a.length;
const sd = (a) => {
  if (a.length < 2) return 0;
  const m = mean(a);
  return Math.sqrt(a.reduce((s, x) => s + (x - m) ** 2, 0) / (a.length - 1));
};

async function call(base, path, token) {
  const r = await fetch(base + path, {
    headers: token ? { authorization: "Bearer " + token } : {},
  });
  await r.text();
  return r.status;
}

async function bench(fn, total, conc) {
  const lat = [];
  let next = 0, bad = 0;
  const t0 = performance.now();
  await Promise.all(
    Array.from({ length: conc }, async () => {
      while (next < total) {
        next += 1;
        const s = performance.now();
        try {
          const c = await fn();
          if (c >= 400) bad += 1;
        } catch { bad += 1; }
        lat.push(performance.now() - s);
      }
    }),
  );
  const wall = performance.now() - t0;
  const sorted = lat.sort((a, b) => a - b);
  return {
    rps: total / (wall / 1000),
    mean: mean(sorted),
    p50: pct(sorted, 50),
    p95: pct(sorted, 95),
    p99: pct(sorted, 99),
    bad,
  };
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
  await post("/entities/register", { address, publicKeyHex: hex(pub), did, role: "holder", label: "Do so mau" });
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
  const pin = await a.post("/ipfs/pin", { json: doc, name: "ss" }, a.token);
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

// Làm nóng kỹ: thí nghiệm này đo chính hiện tượng quá độ, nên phải loại bỏ
// phần quá độ của LẦN ĐẦU TIÊN, nếu không nó sẽ nhiễm vào mức số mẫu nhỏ nhất.
console.log("Làm nóng…");
for (const [, b, t] of BACKENDS) {
  for (const mk of Object.values(ROUTES)) await bench(mk(b, t), 400, CONC);
}

console.log(`\nSố mẫu: ${SIZES.join(", ")} | đồng thời ${CONC} | ${REPEATS} lượt mỗi mức\n`);
const data = [];
for (const [tag, base, tok] of BACKENDS) {
  for (const [route, mk] of Object.entries(ROUTES)) {
    console.log(`  ${tag} ${route}`);
    for (const n of SIZES) {
      const runs = [];
      for (let i = 0; i < REPEATS; i++) {
        runs.push(await bench(mk(base, tok), n, CONC));
        await sleep(100);
      }
      const p95s = runs.map((r) => r.p95);
      const rpss = runs.map((r) => r.rps);
      const row = {
        backend: tag, route, n, repeats: REPEATS, conc: CONC,
        p95_mean: mean(p95s), p95_sd: sd(p95s), p95_cv: (sd(p95s) / mean(p95s)) * 100,
        p95_min: Math.min(...p95s), p95_max: Math.max(...p95s),
        rps_mean: mean(rpss), rps_sd: sd(rpss), rps_cv: (sd(rpss) / mean(rpss)) * 100,
        p50_mean: mean(runs.map((r) => r.p50)),
        bad: runs.reduce((s, r) => s + r.bad, 0),
      };
      data.push(row);
      console.log(
        `    n=${String(n).padStart(4)}  p95 ${row.p95_mean.toFixed(1).padStart(6)} ± ${row.p95_sd.toFixed(1).padStart(5)} ms` +
        `  CV ${row.p95_cv.toFixed(1).padStart(5)}%` +
        `   yc/s ${row.rps_mean.toFixed(0).padStart(5)}  CV ${row.rps_cv.toFixed(1).padStart(5)}%` +
        `   lỗi ${row.bad}`,
      );
    }
  }
}

mkdirSync(OUT, { recursive: true });
writeFileSync(`${OUT}/samplesize.json`, JSON.stringify({
  meta: { startedAt: new Date().toISOString(), conc: CONC, repeats: REPEATS, sizes: SIZES, probeDid },
  data,
}, null, 2));
console.log(`\nXong. ${OUT}/samplesize.json`);
