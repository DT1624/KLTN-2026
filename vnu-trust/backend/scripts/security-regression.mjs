// Kiểm thử hồi quy cho các phát hiện của đợt rà soát bảo mật (docs/SECURITY_REVIEW.md).
//   API_BASE=http://localhost:4010/api node scripts/security-regression.mjs
// Chạy được ở cả hai chế độ VERIFY_ONCHAIN. Mỗi phép gắn mã phát hiện tương ứng;
// phép "B8-…" là rào chắn trước đây không bộ kiểm thử nào bắt được khi bị phá.
import { Account } from "@aptos-labs/ts-sdk";
import { createHash, randomBytes, randomUUID } from "node:crypto";

const API = process.env.API_BASE ?? "http://localhost:4000/api";
const results = [];
const check = (name, passed, detail = "") => {
  results.push({ name, passed });
  console.log(`${passed ? "  PASS" : "  FAIL"}  ${name}${detail ? "  → " + detail : ""}`);
};
const OFFLINE = await fetch(API + "/health").then((r) => r.json()).then((j) => j?.data?.verifyOnChain === false).catch(() => false);

async function call(method, path, body, token, raw) {
  const res = await fetch(API + path, {
    method,
    headers: { "content-type": "application/json", ...(token ? { authorization: "Bearer " + token } : {}) },
    body: raw ?? (body ? JSON.stringify(body) : undefined),
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text.slice(0, 200); }
  return { status: res.status, data };
}
function canonical(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
}
const sha3 = (v) => "0x" + createHash("sha3-256").update(typeof v === "string" ? v : canonical(v)).digest("hex");
const fakeTx = () => "0x" + randomBytes(32).toString("hex");
const fakeCid = () => "b" + Array.from(randomBytes(58), (b) => "abcdefghijklmnopqrstuvwxyz234567"[b % 32]).join("");
const errOf = (r) => (typeof r.data === "object" ? r.data?.error : r.data) ?? "";

function newAccount() {
  const acct = Account.generate();
  return { acct, address: acct.accountAddress.toStringLong(), pub: acct.publicKey.toString() };
}
async function login(a, address = a.address) {
  const ch = await call("POST", "/auth/challenge", { address });
  if (ch.status !== 200) return { status: ch.status };
  const signature = a.acct.sign(new TextEncoder().encode(ch.data.data.message)).toString();
  const vf = await call("POST", "/auth/verify", { address, nonce: ch.data.data.nonce, signature });
  return { status: vf.status, token: vf.data?.data?.token, nonce: ch.data.data.nonce, signature };
}
async function actor(role, label = "Kiểm thử bảo mật") {
  const a = newAccount();
  const r = await call("POST", "/entities/register", { address: a.address, publicKeyHex: a.pub, did: `did:vnu:${role}:${a.address}`, role, label });
  if (r.status !== 201) throw new Error(`đăng ký ${role} lỗi ${r.status}: ${errOf(r)}`);
  return { ...a, did: `did:vnu:${role}:${a.address}`, token: (await login(a)).token };
}

console.log("\n=== S-01. Địa chỉ phải gắn với khoá công khai, và ở dạng chuẩn ===");
{
  const victim = newAccount(), atk = newAccount();
  const r = await call("POST", "/entities/register", { address: victim.address, publicKeyHex: atk.pub, did: `did:vnu:holder:${victim.address}`, role: "holder", label: "Kẻ mạo danh" });
  check("S-01 đăng ký địa chỉ người khác bằng khoá của mình → 400", r.status === 400, `${r.status} ${errOf(r)}`);
  const short = "0x" + victim.address.slice(2).replace(/^0+/, "").slice(0, 63) ;
  const s = newAccount();
  const trimmed = "0x" + s.address.slice(3); // bỏ một chữ số đầu: dạng rút gọn hoặc địa chỉ khác
  const r2 = await call("POST", "/entities/register", { address: trimmed, publicKeyHex: s.pub, did: `did:vnu:admin:${trimmed}`, role: "admin", label: "Rút gọn" });
  check("S-01 địa chỉ rút gọn/không khớp khoá (vai trò admin) → 400", r2.status === 400, `${r2.status}`);
  const up = newAccount();
  const upper = "0x" + up.address.slice(2).toUpperCase();
  const r3 = await call("POST", "/entities/register", { address: upper, publicKeyHex: up.pub, did: `did:vnu:holder:${up.address}`, role: "holder", label: "Chữ hoa" });
  check("S-01 địa chỉ chữ hoa được chuẩn hoá về chữ thường → 201", r3.status === 201 && r3.data?.data?.address === up.address, `${r3.status} ${r3.data?.data?.address ?? errOf(r3)}`);
  void short;
}

console.log("\n=== B8. Rào chắn trước đây không có test bắt ===");
const issuer = await actor("issuer"), issuer2 = await actor("issuer"), holder = await actor("holder"), other = await actor("holder");
const admin = await actor("admin");
{
  // nonce của B dùng cho A
  const ch = await call("POST", "/auth/challenge", { address: holder.address });
  const msgForOther = ch.data.data.message.replace(holder.address, other.address);
  const sig = other.acct.sign(new TextEncoder().encode(msgForOther)).toString();
  const r = await call("POST", "/auth/verify", { address: other.address, nonce: ch.data.data.nonce, signature: sig });
  check("B8-T2 nonce của địa chỉ khác bị từ chối", r.status === 401, `${r.status}`);

  const r2 = await call("POST", "/entities/register", { ...(() => { const a = newAccount(); return { address: a.address, publicKeyHex: a.pub }; })(), did: `did:vnu:holder:${holder.address}`, role: "holder", label: "DID người khác" });
  check("B8-T12 DID không bám theo địa chỉ ví → 400", r2.status === 400, `${r2.status}`);
}

async function issue(by, to, extraSubject = {}, overrides = {}) {
  const vcId = "urn:uuid:" + randomUUID();
  const vcJson = { id: vcId, issuer: by.did, credentialSubject: { id: to.did, ...extraSubject } };
  const body = {
    vcId, onChainVcId: 0, holderDid: to.did, holderAddress: to.address, vcType: 1, ipfsCid: fakeCid(),
    vcIdHash: sha3(vcId), contentHash: sha3(vcJson), proofValue: "z".repeat(32), vcJson,
    issuedAt: new Date().toISOString(), expiresAt: null, txHash: fakeTx(), ...overrides,
  };
  return { vcId, r: await call("POST", "/issuer/credentials", body, by.token) };
}
if (OFFLINE) {
  const { r: bad } = await issue(issuer, holder, {}, { contentHash: sha3({ khac: 1 }) });
  check("B8-T10 hash nội dung VC sai → 400", bad.status === 400, `${bad.status}`);
  const { vcId, r } = await issue(issuer, holder);
  check("(chuẩn bị) cấp VC cho holder", r.status === 201, `${r.status} ${errOf(r)}`);
  const v = encodeURIComponent(vcId);
  check("B8-T3 holder khác đọc VC → 403", (await call("GET", `/holder/credentials/${v}`, null, other.token)).status === 403);
  check("B8-T11 issuer khác đọc VC → 403", (await call("GET", `/issuer/credentials/${v}`, null, issuer2.token)).status === 403);
  const t4 = await call("POST", `/issuer/credentials/${v}/suspend`, { reason: "không phải của tôi", txHash: fakeTx() }, issuer2.token);
  check("B8-T4 issuer khác tạm ngưng VC → 403", t4.status === 403, `${t4.status}`);
  const s = await call("POST", `/issuer/credentials/${v}/suspend`, { reason: "kiểm thử", txHash: fakeTx() }, issuer.token);
  const t5 = await call("POST", `/admin/credentials/${v}/reinstate`, { reason: "tự bật", txHash: fakeTx() }, issuer.token);
  check("B8-T5 issuer tự kích hoạt lại VC → 403", s.status === 200 && t5.status === 403, `${s.status}/${t5.status}`);

  console.log("\n=== S-05. Tuần tự hoá tất định giống JavaScript ở cả hai bản ===");
  for (const [label, extra] of [["dấu &", { faculty: "Kinh tế & QTKD" }], ["dấu < >", { note: "a<b>c" }],
    ["số thực", { gpa: 3.75, big: 1234567.5, tiny: 1e-7 }], ["khoá ngoài BMP", { "😀": 1, "！": 2 }]]) {
    const { r: x } = await issue(issuer, holder, extra);
    check(`S-05 cấp VC chứa ${label}`, x.status === 201, `${x.status} ${errOf(x)}`);
  }
} else {
  console.log("  (bỏ qua nhóm cấp VC — chế độ nghiêm ngặt cần giao dịch thật)");
}

console.log("\n=== S-03 / P-05. Dữ liệu cá nhân trên tuyến công khai ===");
{
  const pinned = await call("POST", "/ipfs/pin", { json: { credentialSubject: { "vnu:studentId": "SV-REVIEW-01" } }, name: "vc" }, holder.token);
  const lk = await call("GET", `/lookup?q=${pinned.data?.data?.cid}`);
  check("S-03 tra CID của văn bằng không lộ nội dung", lk.status === 200 && !JSON.stringify(lk.data).includes("SV-REVIEW-01"), `${lk.status}`);
  const pub = await call("GET", `/entities/by-address/${holder.address}`);
  check("P-05 hồ sơ công khai không lộ label", pub.status === 200 && pub.data?.data?.label === null && pub.data?.data?.did === holder.did, `${pub.status} label=${JSON.stringify(pub.data?.data?.label)}`);
}

console.log("\n=== S-07. Giới hạn dung lượng ghim ===");
{
  const big = await call("POST", "/ipfs/pin", { json: { x: "a".repeat(300 * 1024) }, name: "lon" }, holder.token);
  check("S-07 ghim 300KB → 413", big.status === 413, `${big.status}`);
  const ok = await call("POST", "/ipfs/pin", { json: { x: "a".repeat(10 * 1024) }, name: "nho" }, holder.token);
  check("S-07 ghim 10KB vẫn được", ok.status === 201, `${ok.status}`);
}

console.log("\n=== L-xx. Đầu vào xấu trả 4xx, không 5xx ===");
{
  const bad = await call("POST", "/auth/challenge", null, null, "{hỏng");
  check("L-02 JSON hỏng → 400", bad.status === 400, `${bad.status} ${errOf(bad)}`);
  const huge = await call("POST", "/auth/challenge", null, null, JSON.stringify({ address: "0x" + "a".repeat(3 * 1024 * 1024) }));
  check("L-02 thân > 2MB → 413", huge.status === 413, `${huge.status}`);
  const a = newAccount();
  const nul = await call("POST", "/entities/register", { address: a.address, publicKeyHex: a.pub, did: `did:vnu:holder:${a.address}`, role: "holder", label: "ab\u0000cd" });
  check("L-03 null byte trong chuỗi → 400", nul.status === 400, `${nul.status}`);
  const st = await call("GET", `/issuer/credentials?status=khong-hop-le`, null, issuer.token);
  check("L-05 ?status không hợp lệ → 400 (cả hai bản)", st.status === 400, `${st.status}`);
  const lim = await call("GET", `/admin/audit?limit=100000`, null, admin.token);
  check("L-05 limit vượt trần → 400 (cả hai bản)", lim.status === 400, `${lim.status}`);
}

console.log("\n=== L-01. JWT chỉ nhận HS256 ===");
{
  // Phải ký HS512 bằng ĐÚNG khoá thì phép này mới chứng minh được việc ghim thuật
  // toán — chữ ký sai thì đằng nào cũng bị từ chối. Khoá đọc cục bộ, không in ra.
  const { createHmac } = await import("node:crypto");
  const { readFileSync } = await import("node:fs");
  let secret = process.env.JWT_SECRET;
  try { secret ??= readFileSync(new URL("../.env", import.meta.url), "utf8").match(/^JWT_SECRET=(.*)$/m)?.[1]?.trim(); } catch { /* không có .env */ }
  if (!secret) {
    console.log("  (bỏ qua — không đọc được JWT_SECRET)");
  } else {
    const [, p] = holder.token.split(".");
    const h512 = Buffer.from(JSON.stringify({ alg: "HS512", typ: "JWT" })).toString("base64url");
    const forged = `${h512}.${p}.${createHmac("sha512", secret).update(`${h512}.${p}`).digest("base64url")}`;
    const r = await call("GET", "/auth/me", null, forged);
    check("L-01 token HS512 ký đúng khoá vẫn bị từ chối", r.status === 401, `${r.status}`);
    check("L-01 token HS256 hợp lệ vẫn dùng được", (await call("GET", "/auth/me", null, holder.token)).status === 200);
  }
}

const failed = results.filter((r) => !r.passed);
console.log(`\n${results.length - failed.length}/${results.length} PASS  — ${failed.length ? failed.length + " FAIL: " + failed.map((f) => f.name).join("; ") : "tất cả đạt"}`);
process.exit(failed.length ? 1 : 0);
