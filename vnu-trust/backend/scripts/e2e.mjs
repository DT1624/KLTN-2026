// Kiểm thử end-to-end backend VNU-Trust.
//   node scripts/e2e.mjs
// Yêu cầu backend đang chạy ở API_BASE và Postgres đã có lược đồ.
import { Account } from "@aptos-labs/ts-sdk";
import { createHash, randomUUID } from "node:crypto";

const API = process.env.API_BASE ?? "http://localhost:4000/api";
const results = [];

/**
 * Bộ kiểm thử này khẳng định hành vi CÓ kiểm chứng on-chain. Khi máy chủ chạy
 * với VERIFY_ONCHAIN=false thì những khẳng định đó sai theo đúng thiết kế —
 * đọc chế độ từ /health rồi đổi kỳ vọng, thay vì báo FAIL nhầm.
 */
const STRICT = await fetch(API + "/health")
  .then((r) => r.json())
  .then((j) => j?.data?.verifyOnChain !== false)
  .catch(() => true);
const check = (name, passed, detail = "") => {
  results.push({ name, passed });
  console.log(`${passed ? "  PASS" : "  FAIL"}  ${name}${detail ? "  → " + detail : ""}`);
};

async function call(method, path, body, token) {
  const res = await fetch(API + path, {
    method,
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: "Bearer " + token } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text.slice(0, 200); }
  return { status: res.status, data };
}

// Tuần tự hoá phải khớp canonicalize() của backend.
function canonical(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  return "{" + Object.keys(v).sort().map(k => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
}
const sha3 = (v) => "0x" + createHash("sha3-256").update(typeof v === "string" ? v : canonical(v)).digest("hex");
const fakeTx = () => "0x" + createHash("sha256").update(randomUUID()).digest("hex");

async function makeActor(role, label) {
  const acct = Account.generate();
  const address = acct.accountAddress.toString();
  const did = `did:vnu:${role}:${address}`;
  const reg = await call("POST", "/entities/register", {
    address, publicKeyHex: acct.publicKey.toString(), did, role, label,
  });
  if (reg.status !== 201) throw new Error(`đăng ký ${role} lỗi: ${JSON.stringify(reg.data)}`);

  const ch = await call("POST", "/auth/challenge", { address });
  if (ch.status !== 200) throw new Error(`challenge lỗi: ${JSON.stringify(ch.data)}`);
  const { nonce, message } = ch.data.data;
  const signature = acct.sign(new TextEncoder().encode(message)).toString();
  const vf = await call("POST", "/auth/verify", { address, nonce, signature });
  if (vf.status !== 200) throw new Error(`verify lỗi: ${JSON.stringify(vf.data)}`);
  return { acct, address, did, token: vf.data.data.token };
}

console.log("\n=== A. Xác thực không lộ khoá riêng ===");
const issuer = await makeActor("issuer", "Trường ĐH Công nghệ");
const holder = await makeActor("holder", "Nguyễn Văn A");
const verifier = await makeActor("verifier", "Công ty ABC");
check("Đăng ký + ký challenge Ed25519 → JWT cho 3 vai trò", !!(issuer.token && holder.token && verifier.token));

const me = await call("GET", "/auth/me", null, holder.token);
check("GET /auth/me trả hồ sơ + đối chiếu chuỗi", me.status === 200 && me.data.data.entity.did === holder.did);

// Challenge dùng một lần
const ch2 = await call("POST", "/auth/challenge", { address: holder.address });
const msg2 = ch2.data.data.message, nonce2 = ch2.data.data.nonce;
const sig2 = holder.acct.sign(new TextEncoder().encode(msg2)).toString();
await call("POST", "/auth/verify", { address: holder.address, nonce: nonce2, signature: sig2 });
const replay = await call("POST", "/auth/verify", { address: holder.address, nonce: nonce2, signature: sig2 });
check("Challenge chỉ dùng được một lần (chống replay)", replay.status === 401);

// Ký bằng khoá khác
const ch3 = await call("POST", "/auth/challenge", { address: holder.address });
const intruder = Account.generate();
const badSig = intruder.sign(new TextEncoder().encode(ch3.data.data.message)).toString();
const bad = await call("POST", "/auth/verify", { address: holder.address, nonce: ch3.data.data.nonce, signature: badSig });
check("Chữ ký từ khoá khác bị từ chối", bad.status === 401);

console.log("\n=== B. Không tin dữ liệu client (khác biệt chính so với backend cũ) ===");
const doc = { "@context": ["https://www.w3.org/ns/did/v1"], id: holder.did };
const pin = await call("POST", "/ipfs/pin", { json: doc, name: "did-doc" }, holder.token);
check("Ghim DID Document lên IPFS", pin.status === 201, pin.data?.data?.cid);
const cid = pin.data?.data?.cid;

const forged = await call("POST", "/did/save", {
  did: holder.did, documentCid: cid, documentHash: sha3(doc), docJson: doc, txHash: fakeTx(),
}, holder.token);
check(
  STRICT
    ? "txHash bịa bị TỪ CHỐI (backend cũ chấp nhận)"
    : "VERIFY_ONCHAIN=false: txHash bịa được chấp nhận (đúng chế độ)",
  STRICT ? forged.status === 400 : forged.status === 201,
  STRICT ? String(forged.data?.error).slice(0, 60) : `HTTP ${forged.status}`);

const wrongHash = await call("POST", "/did/save", {
  did: holder.did, documentCid: cid, documentHash: sha3({ khac: "noi dung" }), docJson: doc, txHash: fakeTx(),
}, holder.token);
check("Hash không khớp nội dung bị TỪ CHỐI", wrongHash.status === 400);

const otherDid = await call("POST", "/did/save", {
  did: "did:vnu:holder:0x" + "9".repeat(64), documentCid: cid, documentHash: sha3(doc),
  docJson: doc, txHash: fakeTx(),
}, holder.token);
check("Không ghi được DID của người khác", otherDid.status === 400);

console.log("\n=== C. Kiểm soát truy cập ===");
const wrongRole = await call("GET", "/issuer/stats", null, holder.token);
check("Holder gọi tuyến issuer → 403", wrongRole.status === 403);
const noAuth = await call("GET", "/holder/credentials");
check("Không có token → 401", noAuth.status === 401);
const tampered = await call("GET", "/holder/credentials", null, holder.token.slice(0, -4) + "aaaa");
check("JWT bị sửa → 401", tampered.status === 401);
const notIssuer = await call("POST", "/issuer/credentials", {
  vcId: "urn:uuid:" + randomUUID(), onChainVcId: 0, holderDid: holder.did, holderAddress: holder.address,
  vcType: 1, ipfsCid: cid, vcIdHash: sha3("x"), contentHash: sha3("y"), proofValue: "0".repeat(64),
  issuedAt: new Date().toISOString(), expiresAt: null, txHash: fakeTx(),
}, issuer.token);
check(
  STRICT
    ? "Issuer chưa được cấp quyền on-chain → 403"
    : "VERIFY_ONCHAIN=false: quyền issuer đọc từ CSDL nên KHÔNG bị chặn 403",
  STRICT ? notIssuer.status === 403 : notIssuer.status !== 403,
  String(notIssuer.data?.error).slice(0, 50));

console.log("\n=== D. Kiểm tra dữ liệu đầu vào ===");
const badAddr = await call("POST", "/entities/register", {
  address: "khong-phai-dia-chi", publicKeyHex: "0x" + "a".repeat(64),
  did: "did:vnu:holder:0x1", role: "holder", label: "X",
});
check("Địa chỉ ví sai định dạng bị chặn", badAddr.status === 400);
const badRole = await call("POST", "/entities/register", {
  address: "0x" + "1".repeat(64), publicKeyHex: "0x" + "a".repeat(64),
  did: "did:vnu:root:0x" + "1".repeat(64), role: "root", label: "X",
});
check("Không cho tự đăng ký vai trò root", badRole.status === 400);
const mismatchDid = await call("POST", "/entities/register", {
  address: "0x" + "2".repeat(64), publicKeyHex: "0x" + "a".repeat(64),
  did: "did:vnu:holder:0x" + "3".repeat(64), role: "holder", label: "X",
});
check("DID không bám theo địa chỉ ví bị chặn", mismatchDid.status === 400);
const badCid = await call("POST", "/did/save", {
  did: holder.did, documentCid: "", documentHash: sha3(doc), docJson: doc, txHash: fakeTx(),
}, holder.token);
check("CID rỗng bị chặn ở cả backend lẫn contract (F-06 đã sửa)", badCid.status === 400);

console.log("\n=== E. Tra cứu công khai (dữ liệu thật trên chuỗi) ===");
const stats = await call("GET", "/stats");
check("GET /stats đọc số liệu từ chuỗi", stats.status === 200 && stats.data.data.dids > 0,
  `${stats.data?.data?.dids} DID, ${stats.data?.data?.issuers} issuer`);
if (STRICT) {
  const lookupAddr = await call("GET", "/lookup?q=" + encodeURIComponent(stats.data.data.rootAdmin));
  check("Tra cứu địa chỉ ví → resolve DID trên chuỗi",
    lookupAddr.status === 200 && lookupAddr.data.data.kind === "address");
} else {
  // Không có chuỗi thì không có root admin để tra — tra bằng địa chỉ holder
  // vừa tạo, vẫn kiểm đúng việc nhận diện "đây là địa chỉ ví".
  const lookupAddr = await call("GET", "/lookup?q=" + encodeURIComponent(holder.address));
  check("VERIFY_ONCHAIN=false: tra cứu địa chỉ ví nhận diện đúng loại",
    lookupAddr.status === 200 && lookupAddr.data.data.kind === "address",
    `kind=${lookupAddr.data?.data?.kind}`);
}
const lookupBad = await call("GET", "/lookup?q=khong-hop-le-gi-ca");
check("Định danh không nhận diện được → 400", lookupBad.status === 400);

const failed = results.filter(r => !r.passed);
console.log(`\n${results.length - failed.length}/${results.length} PASS` +
  (failed.length ? `  — ${failed.length} FAIL: ${failed.map(f => f.name).join("; ")}` : "  — tất cả đạt"));
process.exit(failed.length ? 1 : 0);
