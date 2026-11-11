// CHỨNG MINH bước "Nội dung văn bằng khớp bản neo trên chuỗi" thực sự bắt được
// việc sửa nội dung — chứ không phải một bước luôn luôn xanh.
//
// Vì sao cần: một bước kiểm tra luôn PASS thì vô dụng hơn là không có, vì nó
// tạo cảm giác an toàn giả. Kịch bản này cấp một văn bằng thật, chạy xác minh
// (phải đạt), rồi SỬA THẲNG nội dung trong CSDL sau lưng ứng dụng, chạy lại
// xác minh (phải hỏng ĐÚNG ở bước toàn vẹn), cuối cùng trả lại như cũ.
//
//   cd backend && node scripts/tamper-check.mjs
//   API_BASE=http://localhost:4001/api node scripts/tamper-check.mjs   # lên Go
import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";
import { randomUUID, createHash } from "node:crypto";
import pg from "pg";
import { readFileSync } from "node:fs";

const API = process.env.API_BASE ?? "http://localhost:4000/api";
// Biến môi trường thắng .env, để dev.sh trỏ được sang CSDL kiểm thử riêng.
const env = {
  ...Object.fromEntries(
    readFileSync(new URL("../.env", import.meta.url), "utf8")
      .split("\n").filter((l) => l.includes("=") && !l.trim().startsWith("#"))
      .map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim()]),
  ),
  ...process.env,
};

const hex = (b) => "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const canon = (v) => v === null || typeof v !== "object" ? JSON.stringify(v)
  : Array.isArray(v) ? "[" + v.map(canon).join(",") + "]"
  : "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
const sha3 = (v) => hex(sha3_256(new TextEncoder().encode(typeof v === "string" ? v : canon(v))));

const call = async (m, p, b, t) => {
  const r = await fetch(API + p, {
    method: m,
    headers: { ...(b ? { "content-type": "application/json" } : {}), ...(t ? { authorization: "Bearer " + t } : {}) },
    body: b ? JSON.stringify(b) : undefined,
  });
  return { status: r.status, data: await r.json().catch(() => null) };
};

const rows = [];
const check = (name, ok, detail = "") => {
  rows.push({ name, ok });
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  → ${detail}` : ""}`);
};

async function actor(role, label) {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  const address = hex(sha3_256(new Uint8Array([...pub, 0x00])));
  const did = `did:vnu:${role}:${address}`;
  await call("POST", "/entities/register", { address, publicKeyHex: hex(pub), did, role, label });
  const ch = await call("POST", "/auth/challenge", { address });
  const sig = hex(ed25519.sign(new TextEncoder().encode(ch.data.data.message), priv));
  const vf = await call("POST", "/auth/verify", { address, nonce: ch.data.data.nonce, signature: sig });
  return { priv, pub, address, did, token: vf.data.data.token };
}

const fakeTx = () => "0x" + createHash("sha256").update(randomUUID()).digest("hex");

console.log("\n=== Dựng một văn bằng thật rồi thử sửa lén ===");

const issuer = await actor("issuer", "Truong kiem thu toan ven");
const holder = await actor("holder", "Sinh vien kiem thu toan ven");

// Cả hai bên đều phải có DID trong chỉ mục thì luồng mới chạy.
for (const a of [issuer, holder]) {
  const doc = { "@context": ["https://www.w3.org/ns/did/v1"], id: a.did };
  const pin = await call("POST", "/ipfs/pin", { json: doc, name: "did" }, a.token);
  await call("POST", "/did/save",
    { did: a.did, documentCid: pin.data.data.cid, documentHash: sha3(doc), docJson: doc, txHash: fakeTx() }, a.token);
}

const vcId = `urn:uuid:${randomUUID()}`;
const vc = {
  "@context": ["https://www.w3.org/2018/credentials/v1"],
  id: vcId,
  type: ["VerifiableCredential", "VNUDegreeCredential"],
  issuer: issuer.did,
  issuanceDate: new Date().toISOString(),
  credentialSubject: { id: holder.did, "vnu:degreeName": "Cu nhan CNTT", "vnu:gpa": "2.50" },
};
const vcPin = await call("POST", "/ipfs/pin", { json: vc, name: "vc" }, issuer.token);
const issued = await call("POST", "/issuer/credentials", {
  vcId, onChainVcId: Math.floor(Math.random() * 1e9),
  holderDid: holder.did, holderAddress: holder.address, vcType: 1,
  ipfsCid: vcPin.data.data.cid, vcIdHash: sha3(vcId), contentHash: sha3(vc),
  proofValue: hex(ed25519.sign(new TextEncoder().encode(canon(vc)), issuer.priv)),
  vcJson: vc, issuedAt: vc.issuanceDate, expiresAt: null, txHash: fakeTx(),
}, issuer.token);
check("Cấp được văn bằng để thử nghiệm", issued.status === 201, `HTTP ${issued.status}`);

const vp = { "@context": ["https://www.w3.org/2018/credentials/v1"], type: ["VerifiablePresentation"], holder: holder.did };
const vpPin = await call("POST", "/ipfs/pin", { json: vp, name: "vp" }, holder.token);
const pres = await call("POST", "/holder/presentations", {
  vpId: `urn:uuid:${randomUUID()}`, vcIds: [vcId], ipfsCid: vpPin.data.data.cid,
  vpHash: sha3(vp), proofValue: hex(ed25519.sign(new TextEncoder().encode(canon(vp)), holder.priv)),
}, holder.token);
const shareToken = pres.data?.data?.shareToken ?? pres.data?.data?.share_token
  ?? pres.data?.data?.token ?? pres.data?.data?.share?.token;
check("Tạo được liên kết chia sẻ", !!shareToken,
  shareToken ? "có token" : `HTTP ${pres.status} ${JSON.stringify(pres.data).slice(0, 200)}`);
if (!shareToken) { console.log("\n  Không tạo được liên kết, dừng sớm."); process.exit(1); }

const integrityCheck = (report) =>
  report?.checks?.find((c) => c.name === "Nội dung văn bằng khớp bản neo trên chuỗi");

const before = await call("POST", `/verify/share/${shareToken}`);
const beforeIntegrity = integrityCheck(before.data?.data);
check("Trước khi sửa: bước toàn vẹn ĐẠT", beforeIntegrity?.passed === true,
  beforeIntegrity ? beforeIntegrity.detail : "không thấy bước toàn vẹn trong báo cáo");

// --- Sửa lén nội dung trong CSDL, đúng kiểu kẻ có quyền ghi vào chỉ mục ---
const client = new pg.Client({
  host: env.DB_HOST, port: Number(env.DB_PORT), database: env.DB_NAME,
  user: env.DB_USER, password: env.DB_PASSWORD,
});
await client.connect();
const original = (await client.query("SELECT vc_json FROM credentials WHERE vc_id = $1", [vcId])).rows[0].vc_json;

const tampered = JSON.parse(JSON.stringify(original));
tampered.credentialSubject["vnu:gpa"] = "4.00";   // sửa điểm
await client.query("UPDATE credentials SET vc_json = $2 WHERE vc_id = $1", [vcId, tampered]);

const after = await call("POST", `/verify/share/${shareToken}`);
const afterReport = after.data?.data;
const afterIntegrity = integrityCheck(afterReport);
check("Sau khi sửa điểm: bước toàn vẹn HỎNG", afterIntegrity?.passed === false,
  afterIntegrity ? afterIntegrity.detail : "không thấy bước toàn vẹn");
check("Toàn bộ kết quả xác minh chuyển thành KHÔNG hợp lệ", afterReport?.overallValid === false,
  `overallValid=${afterReport?.overallValid}`);

// Bước "còn hiệu lực" VẪN đạt — đó chính là lý do phải có bước toàn vẹn riêng:
// sửa nội dung không hề làm văn bằng bị thu hồi.
const stillActive = afterReport?.checks?.find((c) => c.name === "Tất cả chứng chỉ còn hiệu lực");
check("Bước 'còn hiệu lực' vẫn đạt — nên một mình nó KHÔNG đủ", stillActive?.passed === true,
  stillActive ? stillActive.detail : "không thấy");

// --- Trả lại như cũ ---
await client.query("UPDATE credentials SET vc_json = $2 WHERE vc_id = $1", [vcId, original]);
const restored = await call("POST", `/verify/share/${shareToken}`);
check("Khôi phục nội dung thì xác minh đạt trở lại",
  integrityCheck(restored.data?.data)?.passed === true);
await client.end();

const failed = rows.filter((r) => !r.ok);
console.log(`\n${rows.length - failed.length}/${rows.length} PASS` +
  (failed.length ? `  — ${failed.length} FAIL:\n  ${failed.map((f) => f.name).join("\n  ")}` : "  — bước toàn vẹn bắt được nội dung bị sửa"));
process.exit(failed.length ? 1 : 0);
