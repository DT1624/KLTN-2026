// Đo hiệu năng hai backend trên cùng một bộ tuyến, cùng một CSDL.
// Chạy trong thư mục frontend hoặc backend (cần @noble).
//   node scripts/perf.mjs
import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";

const TS = process.env.TS_BASE ?? "http://localhost:4000/api";
const GO = process.env.GO_BASE ?? "http://localhost:4001/api";
const hex = (b) => "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");

async function call(base, m, p, b, t) {
  const r = await fetch(base + p, {
    method: m,
    headers: { ...(b ? { "content-type": "application/json" } : {}), ...(t ? { authorization: "Bearer " + t } : {}) },
    body: b ? JSON.stringify(b) : undefined,
  });
  await r.text();
  return r.status;
}

/** Trả phân vị thứ p của một mảng đã sắp xếp. */
const pct = (sorted, p) => sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))];

/**
 * Chạy `total` yêu cầu với tối đa `conc` yêu cầu đồng thời, đo độ trễ từng cái.
 * Đo cả p95 chứ không chỉ trung bình: trung bình che mất đuôi chậm, mà đuôi
 * chậm mới là thứ người dùng thực sự cảm thấy.
 */
async function bench(name, fn, { total = 120, conc = 12 } = {}) {
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
  lat.sort((a, b) => a - b);
  return {
    name,
    rps: total / (wall / 1000),
    p50: pct(lat, 50),
    p95: pct(lat, 95),
    max: lat[lat.length - 1],
    codes,
    // 429 là hạn mức đang làm đúng việc của nó, không phải lỗi hệ thống —
    // nhưng nếu có 429 thì số đo độ trễ vô nghĩa, phải nâng hạn mức rồi đo lại.
    throttled: codes[429] ?? 0,
    errors: Object.entries(codes)
      .filter(([c]) => c === "err" || (Number(c) >= 400 && Number(c) !== 429))
      .reduce((n, [, v]) => n + v, 0),
  };
}

async function login(base) {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  const address = hex(sha3_256(new Uint8Array([...pub, 0x00])));
  const did = `did:vnu:holder:${address}`;
  await call(base, "POST", "/entities/register", { address, publicKeyHex: hex(pub), did, role: "holder", label: "Do hieu nang" });
  const ch = await fetch(base + "/auth/challenge", {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ address }),
  }).then((r) => r.json());
  const sig = hex(ed25519.sign(new TextEncoder().encode(ch.data.message), priv));
  const vf = await fetch(base + "/auth/verify", {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ address, nonce: ch.data.nonce, signature: sig }),
  }).then((r) => r.json());
  return vf.data.token;
}

const tokTS = await login(TS);
const tokGO = await login(GO);

// Tuyến resolve/lookup phải làm việc thật chứ không trả 404 sớm, nếu không
// con số đo được chỉ là tốc độ trả lỗi. Tạo sẵn một DID có thật để dò.
async function seedDid(base) {
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

  await post("/entities/register", { address, publicKeyHex: hex(pub), did, role: "holder", label: "Moc do hieu nang" });
  const ch = await post("/auth/challenge", { address });
  const vf = await post("/auth/verify", {
    address, nonce: ch.data.nonce,
    signature: hex(ed25519.sign(new TextEncoder().encode(ch.data.message), priv)),
  });

  const doc = { "@context": ["https://www.w3.org/ns/did/v1"], id: did };
  const pin = await post("/ipfs/pin", { json: doc, name: "perf" }, vf.data.token);
  const canon = (v) => (v === null || typeof v !== "object" ? JSON.stringify(v)
    : Array.isArray(v) ? "[" + v.map(canon).join(",") + "]"
    : "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}");
  const saved = await post("/did/save", {
    did, documentCid: pin.data.cid,
    documentHash: hex(sha3_256(new TextEncoder().encode(canon(doc)))),
    docJson: doc, txHash: "0x" + "cd".repeat(32),
  }, vf.data.token);
  return saved?.success ? did : null;
}

const probeDid = process.env.PROBE_DID ?? (await seedDid(TS));
if (!probeDid) {
  console.error("Không tạo được DID mẫu — cần VERIFY_ONCHAIN=false để chạy phép đo này.");
  process.exit(1);
}

const suites = [
  ["GET /health        ", (b) => () => call(b, "GET", "/health")],
  ["GET /stats         ", (b) => () => call(b, "GET", "/stats")],
  ["GET /did/resolve   ", (b) => () => call(b, "GET", "/did/resolve?did=" + encodeURIComponent(probeDid))],
  ["GET /lookup        ", (b) => () => call(b, "GET", "/lookup?q=" + encodeURIComponent(probeDid))],
  ["GET /auth/me       ", (b, t) => () => call(b, "GET", "/auth/me", null, t)],
  ["GET /holder/creds  ", (b, t) => () => call(b, "GET", "/holder/credentials", null, t)],
];

console.log("\n  tuyến                 backend    req/s      p50       p95       max     ghi chú");
console.log("  " + "─".repeat(74));
const slow = [];
for (const [label, mk] of suites) {
  for (const [tag, base, tok] of [["TS", TS, tokTS], ["GO", GO, tokGO]]) {
    const r = await bench(label, mk(base, tok));
    const f = (n) => n.toFixed(1).padStart(7) + "ms";
    const note = r.throttled ? `429×${r.throttled}` : r.errors ? `lỗi×${r.errors}` : "—";
    console.log(`  ${label}   ${tag}    ${r.rps.toFixed(0).padStart(6)}  ${f(r.p50)}  ${f(r.p95)}  ${f(r.max)}  ${note.padStart(8)}`);
    if (r.throttled > 0) {
      slow.push(`${label.trim()} (${tag}) dính hạn mức ${r.throttled}/${120} lần — nâng RATE_LIMIT_PER_MIN rồi đo lại`);
    } else if (r.p95 > 500) {
      slow.push(`${label.trim()} (${tag}) p95 ${r.p95.toFixed(0)}ms`);
    }
    if (r.errors > 0) {
      slow.push(`${label.trim()} (${tag}) có ${r.errors} lỗi: ${JSON.stringify(r.codes)}`);
    }
  }
}

console.log("");
if (slow.length) {
  console.log("  CẦN XEM LẠI:\n   - " + slow.join("\n   - "));
  process.exit(1);
}
console.log("  Không tuyến nào vượt ngưỡng p95 500ms và không có lỗi.");
