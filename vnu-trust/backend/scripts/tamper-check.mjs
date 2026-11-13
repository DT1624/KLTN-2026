// CHỨNG MINH bước "Nội dung văn bằng khớp bản neo trên chuỗi" thực sự bắt được
// việc sửa nội dung — chứ không phải một bước luôn luôn xanh.
//
// Vì sao cần: một bước kiểm tra luôn PASS thì vô dụng hơn là không có, vì nó
// tạo cảm giác an toàn giả. Kịch bản này cấp một văn bằng, xác minh bản trình bày
// nguyên vẹn (phải đạt), rồi xác minh bản trình bày có nội dung bị sửa (phải hỏng
// ĐÚNG ở bước toàn vẹn).
//
// P3 (13/11/2026): máy chủ không còn giữ nội dung văn bằng, nên không còn "sửa thẳng
// trong CSDL". Mối đe doạ thực tế là nội dung bị sửa trong BẢN TRÌNH BÀY: holder tự
// sửa rồi ký (chỉ bước 7 bắt được), hoặc bị sửa trên đường tới người xác minh.
//
//   cd backend && node scripts/tamper-check.mjs
//   API_BASE=http://localhost:4001/api node scripts/tamper-check.mjs   # lên Go
import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";
import { randomUUID, createHash } from "node:crypto";
import { fakeEnvelope, fakeShareBlob } from "./lib-envelope.mjs";

const API = process.env.API_BASE ?? "http://localhost:4000/api";

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
// P3: IPFS chỉ nhận phong bì mã hoá; nội dung văn bằng không rời thiết bị dạng rõ.
const vcPin = await call("POST", "/ipfs/pin", { json: fakeEnvelope(sha3(vcId), holder.address, issuer.address), name: "vc" }, issuer.token);
const issued = await call("POST", "/issuer/credentials", {
  vcId, onChainVcId: Math.floor(Math.random() * 1e9),
  holderDid: holder.did, holderAddress: holder.address, vcType: 1,
  ipfsCid: vcPin.data.data.cid, vcIdHash: sha3(vcId), contentHash: sha3(vc),
  proofValue: hex(ed25519.sign(new TextEncoder().encode(canon(vc)), issuer.priv)),
  issuedAt: vc.issuanceDate, expiresAt: null, txHash: fakeTx(),
}, issuer.token);
check("Cấp được văn bằng để thử nghiệm", issued.status === 201, `HTTP ${issued.status} ${issued.data?.error ?? ""}`);

// Holder tạo bản trình bày (bản rõ chỉ nằm ở trình duyệt; IPFS giữ bản mã) và ký nó.
async function share(credential) {
  const vp = { "@context": ["https://www.w3.org/2018/credentials/v1"], type: ["VerifiablePresentation"],
    holder: holder.did, verifiableCredential: [credential] };
  const vpPin = await call("POST", "/ipfs/pin", { json: fakeShareBlob(), name: "vp" }, holder.token);
  const pres = await call("POST", "/holder/presentations", {
    vpId: `urn:uuid:${randomUUID()}`, vcIds: [vcId], ipfsCid: vpPin.data.data.cid,
    vpHash: sha3(vp), proofValue: hex(ed25519.sign(new TextEncoder().encode(canon(vp)), holder.priv)),
  }, holder.token);
  return { vp, token: pres.data?.data?.share?.token, pres };
}
const honest = await share(vc);
check("Tạo được liên kết chia sẻ", !!honest.token,
  honest.token ? "có token" : `HTTP ${honest.pres.status} ${JSON.stringify(honest.pres.data).slice(0, 200)}`);
if (!honest.token) { console.log("\n  Không tạo được liên kết, dừng sớm."); process.exit(1); }

const step = (report, name) => report?.checks?.find((c) => c.name === name);
const INTEGRITY = "Nội dung văn bằng khớp bản neo trên chuỗi";
const verify = async (token, vp) => (await call("POST", `/verify/share/${token}`, { vp })).data?.data;

const before = await verify(honest.token, honest.vp);
check("Văn bằng nguyên vẹn: bước toàn vẹn ĐẠT và kết quả hợp lệ",
  step(before, INTEGRITY)?.passed === true && before?.overallValid === true,
  step(before, INTEGRITY)?.detail ?? "không thấy bước toàn vẹn");

// --- Kịch bản 1: holder sửa điểm rồi tự ký bản trình bày ---
// Chữ ký và hash bản trình bày đều khớp (chính holder ký), văn bằng vẫn "còn hiệu
// lực" — chỉ bước toàn vẹn (hash nội dung ↔ bản neo trên chuỗi) bắt được.
const forgedVc = JSON.parse(JSON.stringify(vc));
forgedVc.credentialSubject["vnu:gpa"] = "4.00";
const forged = await share(forgedVc);
const after = await verify(forged.token, forged.vp);
check("Holder sửa điểm rồi tự ký: bước toàn vẹn HỎNG", step(after, INTEGRITY)?.passed === false,
  step(after, INTEGRITY)?.detail ?? "không thấy bước toàn vẹn");
check("…trong khi chữ ký và hash bản trình bày vẫn đạt (nên chỉ bước 7 bắt được)",
  step(after, "Chữ ký của người trình bày")?.passed === true && step(after, "Toàn vẹn nội dung VP")?.passed === true);
check("Toàn bộ kết quả xác minh chuyển thành KHÔNG hợp lệ", after?.overallValid === false,
  `overallValid=${after?.overallValid}`);
// Bước "còn hiệu lực" VẪN đạt — đó chính là lý do phải có bước toàn vẹn riêng.
check("Bước 'còn hiệu lực' vẫn đạt — nên một mình nó KHÔNG đủ",
  step(after, "Tất cả chứng chỉ còn hiệu lực")?.passed === true,
  step(after, "Tất cả chứng chỉ còn hiệu lực")?.detail ?? "không thấy");

// --- Kịch bản 2: sửa bản trình bày trên đường tới người xác minh ---
const mitm = JSON.parse(JSON.stringify(honest.vp));
mitm.verifiableCredential[0].credentialSubject["vnu:gpa"] = "4.00";
const relayed = await verify(honest.token, mitm);
check("Sửa bản trình bày sau khi chia sẻ: bước hash bản trình bày VÀ bước toàn vẹn cùng HỎNG",
  step(relayed, "Toàn vẹn nội dung VP")?.passed === false && step(relayed, INTEGRITY)?.passed === false
  && relayed?.overallValid === false);

// Xác minh không lưu trạng thái: gửi lại đúng bản gốc thì đạt trở lại.
const restored = await verify(honest.token, honest.vp);
check("Gửi lại bản trình bày gốc thì xác minh đạt trở lại", step(restored, INTEGRITY)?.passed === true && restored?.overallValid === true);

const failed = rows.filter((r) => !r.ok);
console.log(`\n${rows.length - failed.length}/${rows.length} PASS` +
  (failed.length ? `  — ${failed.length} FAIL:\n  ${failed.map((f) => f.name).join("\n  ")}` : "  — bước toàn vẹn bắt được nội dung bị sửa"));
process.exit(failed.length ? 1 : 0);
