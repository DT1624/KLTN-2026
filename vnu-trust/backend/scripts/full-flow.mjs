// Kiểm thử TOÀN BỘ LUỒNG NGHIỆP VỤ từ đầu đến cuối.
// Chạy được cả phần GHI nhờ VERIFY_ONCHAIN=false (không cần giao dịch thật).
//   node scripts/full-flow.mjs                              # backend TS
//   API_BASE=http://localhost:4001/api node scripts/full-flow.mjs   # backend Go
import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";
import { randomUUID, createHash } from "node:crypto";

const API = process.env.API_BASE ?? "http://localhost:4000/api";
const results = [];
const check = (n, ok, d = "") => { results.push({ n, ok }); console.log(`${ok ? "  PASS" : "  FAIL"}  ${n}${d ? "  → " + d : ""}`); };
const hex = (b) => "0x" + Array.from(b).map(x => x.toString(16).padStart(2, "0")).join("");
const fakeTx = () => "0x" + createHash("sha256").update(randomUUID()).digest("hex");
const canon = (v) => v === null || typeof v !== "object" ? JSON.stringify(v)
  : Array.isArray(v) ? "[" + v.map(canon).join(",") + "]"
  : "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
const sha3 = (v) => hex(sha3_256(new TextEncoder().encode(typeof v === "string" ? v : canon(v))));

async function call(m, p, b, t) {
  const r = await fetch(API + p, { method: m,
    headers: { ...(b ? {"content-type":"application/json"} : {}), ...(t ? {authorization:"Bearer "+t} : {}) },
    body: b ? JSON.stringify(b) : undefined });
  const x = await r.text(); let d; try { d = JSON.parse(x); } catch { d = x.slice(0,300); }
  return { status: r.status, data: d };
}

async function actor(role, label) {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  const address = hex(sha3_256(new Uint8Array([...pub, 0x00])));
  const did = `did:vnu:${role}:${address}`;
  const reg = await call("POST", "/entities/register", { address, publicKeyHex: hex(pub), did, role, label });
  if (reg.status !== 201) throw new Error(`đăng ký ${role}: ${JSON.stringify(reg.data)}`);
  const ch = await call("POST", "/auth/challenge", { address });
  const sig = hex(ed25519.sign(new TextEncoder().encode(ch.data.data.message), priv));
  const vf = await call("POST", "/auth/verify", { address, nonce: ch.data.data.nonce, signature: sig });
  if (vf.status !== 200) throw new Error(`đăng nhập ${role}: ${JSON.stringify(vf.data)}`);
  return { priv, pub, address, did, token: vf.data.data.token, sign: (m) => hex(ed25519.sign(new TextEncoder().encode(m), priv)) };
}

console.log(`\n### Backend: ${API}\n`);
console.log("=== 1. Thiết lập các vai trò ===");
const issuer = await actor("issuer", "Trường ĐH Công nghệ");
const holder = await actor("holder", "Nguyễn Văn A");
const verifier = await actor("verifier", "Công ty ABC");
const admin = await actor("admin", "Phòng Đào tạo");
check("Tạo 4 vai trò và đăng nhập", [issuer, holder, verifier, admin].every(a => a.token));

console.log("\n=== 2. Đăng ký DID cho holder ===");
const didDoc = {
  "@context": ["https://www.w3.org/ns/did/v1"],
  id: holder.did,
  verificationMethod: [{ id: `${holder.did}#key-1`, type: "Ed25519VerificationKey2020",
    controller: holder.did, publicKeyMultibase: holder.pub ? hex(holder.pub) : "" }],
  authentication: [`${holder.did}#key-1`],
};
const pin1 = await call("POST", "/ipfs/pin", { json: didDoc, name: "did-doc" }, holder.token);
check("Ghim DID Document lên IPFS", pin1.status === 201, pin1.data?.data?.cid?.slice(0, 24) + "…");
const didSave = await call("POST", "/did/save", {
  did: holder.did, documentCid: pin1.data.data.cid, documentHash: sha3(didDoc),
  docJson: didDoc, txHash: fakeTx(),
}, holder.token);
check("Lưu DID (kèm kiểm hash khớp nội dung)", didSave.status === 201);
const resolve = await call("GET", `/did/resolve?did=${encodeURIComponent(holder.did)}`);
check("Resolve DID công khai", resolve.status === 200 && resolve.data.data.did === holder.did,
  `nguồn: ${resolve.data?.data?.source}, toàn vẹn: ${resolve.data?.data?.integrityOk}`);

console.log("\n=== 3. Issuer cấp văn bằng ===");
const vcId = `urn:uuid:${randomUUID()}`;
const onChainVcId = Math.floor(Date.now() / 1000) * 100 + Math.floor(Math.random() * 100);
const issuedAt = new Date().toISOString();
const vc = {
  "@context": ["https://www.w3.org/2018/credentials/v1", { vnu: "https://vnu.edu.vn/credentials/v1#" }],
  id: vcId, type: ["VerifiableCredential", "VNUDegreeCredential"],
  issuer: issuer.did, issuanceDate: issuedAt,
  credentialSubject: { id: holder.did, "vnu:studentId": "21020123",
    "vnu:degreeName": "Cử nhân Công nghệ thông tin", "vnu:faculty": "Trường ĐH Công nghệ",
    "vnu:gpa": "3.42", "vnu:graduationYear": "2026" },
};
const pin2 = await call("POST", "/ipfs/pin", { json: vc, name: "vc" }, issuer.token);
const issue = await call("POST", "/issuer/credentials", {
  vcId, onChainVcId, holderDid: holder.did, holderAddress: holder.address,
  vcType: 1, ipfsCid: pin2.data.data.cid, vcIdHash: sha3(vcId), contentHash: sha3(vc),
  proofValue: issuer.sign(canon(vc)), vcJson: vc, issuedAt, expiresAt: null, txHash: fakeTx(),
}, issuer.token);
check("Issuer cấp VC", issue.status === 201, `HTTP ${issue.status} ${issue.status !== 201 ? JSON.stringify(issue.data).slice(0,120) : ""}`);

const stats1 = await call("GET", "/issuer/stats", null, issuer.token);
check("Thống kê issuer đúng", stats1.data?.data?.active === 1, JSON.stringify(stats1.data?.data));

const wallet = await call("GET", "/holder/credentials", null, holder.token);
check("Holder thấy VC trong ví", wallet.data?.data?.length === 1);

console.log("\n=== 4. Holder tạo bản trình bày và chia sẻ ===");
const vp = { "@context": ["https://www.w3.org/2018/credentials/v1"], type: ["VerifiablePresentation"],
  holder: holder.did, verifiableCredential: [vc], created: new Date().toISOString() };
const pin3 = await call("POST", "/ipfs/pin", { json: vp, name: "vp" }, holder.token);
const vpId = `urn:uuid:${randomUUID()}`;
const vpRes = await call("POST", "/holder/presentations", {
  vpId, verifierDid: null, vcIds: [vcId], ipfsCid: pin3.data.data.cid,
  vpHash: sha3(vp), proofValue: holder.sign(canon(vp)), challenge: null, ttlSeconds: 3600,
}, holder.token);
check("Tạo VP + liên kết chia sẻ", vpRes.status === 201 && !!vpRes.data?.data?.share?.token);
const token = vpRes.data?.data?.share?.token;

if (!token) {
  check("DỪNG: không có liên kết chia sẻ, các bước sau không chạy được", false,
    JSON.stringify(vpRes.data).slice(0, 200));
  const f = results.filter(r => !r.ok);
  console.log(`\n${results.length - f.length}/${results.length} PASS — ${f.length} FAIL`);
  process.exit(1);
}
const preview = await call("GET", `/verify/share/${token}`);
check("Bên xác minh mở được liên kết (công khai)", preview.status === 200 && preview.data.data.vcIds.length === 1);

console.log("\n=== 5. Xác minh đầy đủ 7 bước ===");
const report = await call("POST", `/verify/share/${token}`);
check("Chạy được quy trình xác minh", report.status === 200);
if (report.data?.data?.checks) {
  for (const c of report.data.data.checks) {
    console.log(`       ${c.passed ? "✓" : "✗"} ${c.name}: ${c.detail}`);
  }
}
check("Chữ ký của holder được xác minh đúng",
  report.data?.data?.checks?.find(c => c.name.includes("Chữ ký"))?.passed === true);
check("Toàn vẹn nội dung VP khớp",
  report.data?.data?.checks?.find(c => c.name.includes("Toàn vẹn"))?.passed === true);

const record = await call("POST", `/verify/share/${token}/record`, null, verifier.token);
check("Verifier lưu kết quả vào lịch sử", record.status === 200);
const hist = await call("GET", "/verify/history", null, verifier.token);
check("Verifier xem được lịch sử", hist.status === 200 && hist.data.data.length >= 1);

console.log("\n=== 6. Thu hồi và hệ quả dây chuyền ===");
const revoke = await call("POST", `/issuer/credentials/${vcId}/revoke`,
  { reason: "Phát hiện sai sót hồ sơ", txHash: fakeTx() }, issuer.token);
check("Issuer thu hồi VC", revoke.status === 200);
const stats2 = await call("GET", "/issuer/stats", null, issuer.token);
check("Thống kê cập nhật sau thu hồi", stats2.data?.data?.revoked === 1, JSON.stringify(stats2.data?.data));

const reVerify = await call("POST", `/verify/share/${token}`);
check("VP chứa VC đã thu hồi -> xác minh THẤT BẠI",
  reVerify.data?.data?.overallValid === false,
  reVerify.data?.data?.credentials?.[0]?.status);

const newVp = await call("POST", "/holder/presentations", {
  vpId: `urn:uuid:${randomUUID()}`, verifierDid: null, vcIds: [vcId],
  ipfsCid: pin3.data.data.cid, vpHash: sha3(vp), proofValue: holder.sign(canon(vp)),
  challenge: null, ttlSeconds: 3600,
}, holder.token);
check("Không tạo được VP mới từ VC đã thu hồi", newVp.status === 400, String(newVp.data?.error).slice(0, 60));

console.log("\n=== 7. Thu hồi liên kết chia sẻ ===");
const shares = await call("GET", "/holder/shares", null, holder.token);
const shareRows = Array.isArray(shares.data?.data) ? shares.data.data : [];
check("Holder xem danh sách liên kết đã chia sẻ", shares.status === 200 && shareRows.length >= 1);
const mine = shareRows.find(r => r.token === token) ?? shareRows[0];
check("Bộ đếm lượt xem có tăng", Number(mine?.view_count ?? mine?.viewCount ?? 0) >= 1,
  `${mine?.view_count ?? mine?.viewCount ?? "không có bản ghi"} lượt`);
const revShare = await call("DELETE", `/holder/shares/${token}`, null, holder.token);
check("Thu hồi liên kết", revShare.status === 200);
const afterRev = await call("GET", `/verify/share/${token}`);
check("Liên kết sau thu hồi trả 410", afterRev.status === 410);

console.log("\n=== 8. Quyền admin ===");
const ov = await call("GET", "/admin/overview", null, admin.token);
check("Admin xem bảng điều khiển", ov.status === 200, `${ov.data?.data?.onChain?.issuers} issuer trên chuỗi`);
const adminIssuers = await call("GET", "/admin/issuers", null, admin.token);
check("Admin liệt kê issuer kèm trạng thái chuỗi", adminIssuers.status === 200);
const holderTryAdmin = await call("GET", "/admin/overview", null, holder.token);
check("Holder không vào được tuyến admin", holderTryAdmin.status === 403);

const chk = await call("GET", `/admin/check/${issuer.address}`, null, admin.token);
check("Admin tra cứu được quyền của một địa chỉ",
  chk.status === 200 && chk.data?.data?.isActiveIssuer === true,
  `isActiveIssuer=${chk.data?.data?.isActiveIssuer}`);

// Nhật ký kiểm toán phải ghi lại đúng ba việc vừa làm trong lần chạy này.
const audit = await call("GET", "/admin/audit?limit=50", null, admin.token);
const auditMine = (Array.isArray(audit.data?.data) ? audit.data.data : [])
  .filter((r) => r.target === holder.did || r.target === vcId);
const acts = new Set(auditMine.map((r) => r.action));
check("Nhật ký kiểm toán ghi lại thao tác của lần chạy này",
  audit.status === 200 && acts.has("did.save") && acts.has("vc.issue") && acts.has("vc.revoke"),
  [...acts].join(", ") || "rỗng");
check("Nhật ký ghi đúng người thực hiện",
  auditMine.find((r) => r.action === "vc.revoke")?.actor === issuer.address,
  auditMine.find((r) => r.action === "vc.revoke")?.actor?.slice(0, 18) + "…");

console.log("\n=== 9. Tra cứu công khai ===");
const lk1 = await call("GET", `/lookup?q=${encodeURIComponent(holder.did)}`);
check("Tra cứu theo DID", lk1.status === 200 && lk1.data.data.kind === "did");
const lk2 = await call("GET", `/lookup?q=${vcId}`);
check("Tra cứu theo mã VC", lk2.status === 200 && lk2.data.data.result.status === "revoked",
  lk2.data?.data?.result?.status);
const lk3 = await call("GET", `/lookup?q=${pin1.data.data.cid}`);
check("Tra cứu theo CID", lk3.status === 200 && lk3.data.data.kind === "cid");

const failed = results.filter(r => !r.ok);
console.log(`\n${results.length - failed.length}/${results.length} PASS` +
  (failed.length ? `  — ${failed.length} FAIL:\n  ${failed.map(f => f.n).join("\n  ")}` : "  — tất cả đạt"));
process.exit(failed.length ? 1 : 0);
