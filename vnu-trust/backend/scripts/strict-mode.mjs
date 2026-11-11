// Chứng minh chế độ offline (VERIFY_ONCHAIN=false) là TUỲ CHỌN và không làm
// hỏng tính chất an toàn cốt lõi. Chạy một tiến trình riêng ở chế độ nghiêm ngặt:
//   VERIFY_ONCHAIN=true PORT=4097 npx tsx src/server.ts &
//   API_BASE=http://localhost:4097/api node scripts/strict-mode.mjs
import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";
import { randomUUID, createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";
const API = process.env.API_BASE ?? "http://localhost:4097/api";
const hex = (b) => "0x" + Array.from(b).map(x => x.toString(16).padStart(2,"0")).join("");
const call = async (m,p,b,t) => { const r = await fetch(API+p,{method:m,headers:{...(b?{"content-type":"application/json"}:{}),...(t?{authorization:"Bearer "+t}:{})},body:b?JSON.stringify(b):undefined}); return {status:r.status, data: await r.json().catch(()=>null)}; };
const canon = (v) => v===null||typeof v!=="object"?JSON.stringify(v):Array.isArray(v)?"["+v.map(canon).join(",")+"]":"{"+Object.keys(v).sort().map(k=>JSON.stringify(k)+":"+canon(v[k])).join(",")+"}";
const sha3 = (v) => hex(sha3_256(new TextEncoder().encode(typeof v==="string"?v:canon(v))));

const priv = ed25519.utils.randomPrivateKey(), pub = ed25519.getPublicKey(priv);
const address = hex(sha3_256(new Uint8Array([...pub,0x00]))), did = `did:vnu:holder:${address}`;
await call("POST","/entities/register",{address,publicKeyHex:hex(pub),did,role:"holder",label:"Kiem thu nghiem ngat"});
const ch = await call("POST","/auth/challenge",{address});
const vf = await call("POST","/auth/verify",{address,nonce:ch.data.data.nonce,signature:hex(ed25519.sign(new TextEncoder().encode(ch.data.data.message),priv))});
const tok = vf.data.data.token;

const doc = {"@context":["https://www.w3.org/ns/did/v1"], id: did};
const pin = await call("POST","/ipfs/pin",{json:doc,name:"d"},tok);
const fakeTx = "0x"+createHash("sha256").update(randomUUID()).digest("hex");
const save = await call("POST","/did/save",{did,documentCid:pin.data.data.cid,documentHash:sha3(doc),docJson:doc,txHash:fakeTx},tok);
const ok1 = save.status === 400 && /giao dịch/i.test(save.data?.error ?? "");
console.log(`  ${ok1?"PASS":"FAIL"}  VERIFY_ONCHAIN=true: /did/save với txHash bịa bị từ chối  → HTTP ${save.status} "${save.data?.error}"`);

// Biến môi trường thắng .env, để dev.sh trỏ được sang CSDL kiểm thử riêng.
const fileEnv = Object.fromEntries(readFileSync(new URL("../.env", import.meta.url), "utf8").split("\n")
  .filter((l) => l.includes("=") && !l.trim().startsWith("#")).map((l) => [l.slice(0, l.indexOf("=")).trim(), l.slice(l.indexOf("=") + 1).trim()]));
const env = { ...fileEnv, ...process.env };
const db = new pg.Client({ host: env.DB_HOST, port: Number(env.DB_PORT), database: env.DB_NAME, user: env.DB_USER, password: env.DB_PASSWORD });
await db.connect();

// Tạo một tài khoản holder. `forceRole` mô phỏng chỉ mục CSDL lệch chuỗi (ví dụ
// quyền bị thu hồi ngoài ứng dụng): rào phía sau vẫn phải chặn.
async function account(label, forceRole) {
  const p = ed25519.utils.randomPrivateKey(), k = ed25519.getPublicKey(p);
  const a = hex(sha3_256(new Uint8Array([...k,0x00])));
  await call("POST","/entities/register",{address:a,publicKeyHex:hex(k),did:`did:vnu:holder:${a}`,role:"holder",label});
  if (forceRole) await db.query("UPDATE entities SET role = $2 WHERE address = $1", [a, forceRole]);
  const c = await call("POST","/auth/challenge",{address:a});
  const v = await call("POST","/auth/verify",{address:a,nonce:c.data.data.nonce,signature:hex(ed25519.sign(new TextEncoder().encode(c.data.data.message),p))});
  return v.data.data.token;
}

// Đăng ký tự khai admin/issuer bị chặn ngay: chuỗi chưa công nhận thì không ghi danh.
const selfAdmin = (() => { const p = ed25519.utils.randomPrivateKey(), k = ed25519.getPublicKey(p); const a = hex(sha3_256(new Uint8Array([...k,0x00]))); return {address:a,publicKeyHex:hex(k),did:`did:vnu:admin:${a}`,role:"admin",label:"Ke tu khai admin"}; })();
const reg = await call("POST","/entities/register",selfAdmin);
const ok0 = reg.status === 403 && /chuỗi/i.test(reg.data?.error ?? "");
console.log(`  ${ok0?"PASS":"FAIL"}  VERIFY_ONCHAIN=true: đăng ký tự khai admin bị từ chối  → HTTP ${reg.status} "${reg.data?.error}"`);

const tok2 = await account("Chi muc lech issuer", "issuer");
const issue = await call("POST","/issuer/credentials",{vcId:`urn:uuid:${randomUUID()}`,onChainVcId:999999,holderDid:did,holderAddress:address,vcType:1,ipfsCid:pin.data.data.cid,vcIdHash:sha3("x"),contentHash:sha3("y"),proofValue:"0x00",vcJson:{},issuedAt:new Date().toISOString(),expiresAt:null,txHash:fakeTx},tok2);
const ok2 = issue.status === 403;
console.log(`  ${ok2?"PASS":"FAIL"}  VERIFY_ONCHAIN=true: chỉ mục ghi issuer nhưng chuỗi không công nhận → 403  → HTTP ${issue.status}`);

// === Tuyến quản trị quyền: vai trò trong CSDL KHÔNG được biến thành quyền thật ===
const tok3 = await account("Chi muc lech admin", "admin");

// Thu hồi phải có hiệu lực NGAY, không đợi JWT (8 giờ) hết hạn.
const tok7 = await account("Admin bi ha quyen", "admin");
const before7 = await call("GET","/admin/audit",null,tok7);
await db.query("UPDATE entities SET role = 'holder' WHERE did = $1", [JSON.parse(Buffer.from(tok7.split(".")[1], "base64url")).did]);
const after7 = await call("GET","/admin/audit",null,tok7);
const ok7 = before7.status === 200 && after7.status === 403;
console.log(`  ${ok7?"PASS":"FAIL"}  hạ quyền admin có hiệu lực ngay với token cũ  → trước ${before7.status}, sau ${after7.status}`);
await db.end();

const grant = await call("POST","/admin/authority/admins",{address,txHash:fakeTx},tok3);
// Phải bị chặn vì KHÔNG phải root trên chuỗi — đọc cả thông điệp để chắc chắn
// dừng đúng chỗ, chứ không phải tình cờ hỏng vì lý do khác.
const ok3 = grant.status === 403 && /root/i.test(grant.data?.error ?? "");
console.log(`  ${ok3?"PASS":"FAIL"}  VERIFY_ONCHAIN=true: admin trong chỉ mục KHÔNG cấp được quyền admin  → HTTP ${grant.status} "${grant.data?.error}"`);

const approve = await call("POST","/admin/authority/issuers",{address,vcTypeMask:1,expiresAt:0,txHash:fakeTx},tok3);
const ok4 = approve.status === 403 && /chuỗi/i.test(approve.data?.error ?? "");
console.log(`  ${ok4?"PASS":"FAIL"}  VERIFY_ONCHAIN=true: tự khai admin KHÔNG phê duyệt được issuer  → HTTP ${approve.status} "${approve.data?.error}"`);

const propose = await call("POST","/admin/authority/root/propose",{address,txHash:fakeTx},tok3);
const ok5 = propose.status === 403;
console.log(`  ${ok5?"PASS":"FAIL"}  VERIFY_ONCHAIN=true: tự khai admin KHÔNG đề cử được root  → HTTP ${propose.status}`);

// Nhận quyền root là tuyến KHÔNG chặn theo vai trò (người được đề cử lúc đó
// chưa phải root). Rào duy nhất là xác minh giao dịch — nên nó phải chặn ở đây.
const accept = await call("POST","/authority/root/accept",{txHash:fakeTx},tok3);
const ok6 = accept.status === 400 && /giao dịch/i.test(accept.data?.error ?? "");
console.log(`  ${ok6?"PASS":"FAIL"}  VERIFY_ONCHAIN=true: nhận quyền root bằng txHash bịa bị từ chối  → HTTP ${accept.status} "${accept.data?.error}"`);

const all = [ok0,ok1,ok2,ok3,ok4,ok5,ok6,ok7];
const passed = all.filter(Boolean).length;
console.log(`\n${passed}/${all.length} PASS` + (passed===all.length ? "  — chế độ nghiêm ngặt giữ nguyên mọi rào chắn" : "  — CÓ RÀO CHẮN BỊ THỦNG"));
process.exit(passed === all.length ? 0 : 1);
