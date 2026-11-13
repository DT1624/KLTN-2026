// Kiểm tra HAI BACKEND TƯƠNG ĐƯƠNG NHAU.
//
// Hai cài đặt (TypeScript cổng 4000, Go cổng 4001) phải trả về cùng mã trạng
// thái và cùng hình dạng dữ liệu cho cùng một yêu cầu. Đây là thứ ràng buộc
// chúng không lệch nhau khi code tiến hoá — thiếu nó thì việc "cùng hợp đồng
// API" chỉ là lời hứa trong tài liệu.
//
//   node scripts/parity.mjs
import { ed25519 } from "@noble/curves/ed25519";
import { sha3_256 } from "@noble/hashes/sha3";

const TS = process.env.TS_BASE ?? "http://localhost:4000/api";
const GO = process.env.GO_BASE ?? "http://localhost:4001/api";

const hex = (b) => "0x" + Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const rows = [];

async function call(base, method, path, body, token) {
  const r = await fetch(base + path, {
    method,
    headers: {
      ...(body ? { "content-type": "application/json" } : {}),
      ...(token ? { authorization: "Bearer " + token } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await r.text();
  let data;
  try { data = JSON.parse(text); } catch { data = text.slice(0, 200); }
  return { status: r.status, data };
}

/** Hình dạng dữ liệu: tập khoá đã sắp xếp, đệ quy — bỏ qua giá trị cụ thể. */
function shape(v, depth = 0) {
  if (depth > 3) return "…";
  if (v === null) return "null";
  if (Array.isArray(v)) return v.length ? `[${shape(v[0], depth + 1)}]` : "[]";
  if (typeof v === "object") {
    return "{" + Object.keys(v).sort().map((k) => `${k}:${shape(v[k], depth + 1)}`).join(",") + "}";
  }
  return typeof v;
}

function compare(name, a, b, { compareShape = true } = {}) {
  const sameStatus = a.status === b.status;
  const sameShape = !compareShape || shape(a.data?.data) === shape(b.data?.data);
  const ok = sameStatus && sameShape;
  rows.push({ name, ok });
  const detail = !sameStatus
    ? `mã khác nhau: TS=${a.status} GO=${b.status}`
    : !sameShape
      ? `hình dạng khác nhau:\n      TS: ${shape(a.data?.data)}\n      GO: ${shape(b.data?.data)}`
      : `cả hai ${a.status}`;
  console.log(`${ok ? "  KHỚP" : "  LỆCH"}  ${name}  → ${detail}`);
  return ok;
}

/** Tạo một tài khoản trên MỘT backend rồi đăng nhập ở CẢ HAI — chứng minh
 *  chúng dùng chung CSDL và chung cách xác thực. */
async function makeActor(role, label) {
  const priv = ed25519.utils.randomPrivateKey();
  const pub = ed25519.getPublicKey(priv);
  const address = hex(sha3_256(new Uint8Array([...pub, 0x00])));
  const did = `did:vnu:${role}:${address}`;

  const reg = await call(TS, "POST", "/entities/register", {
    address, publicKeyHex: hex(pub), did, role, label,
  });
  if (reg.status !== 201) throw new Error(`đăng ký lỗi: ${JSON.stringify(reg.data)}`);

  const login = async (base) => {
    const ch = await call(base, "POST", "/auth/challenge", { address });
    if (ch.status !== 200) throw new Error(`challenge lỗi tại ${base}: ${JSON.stringify(ch.data)}`);
    const sig = hex(ed25519.sign(new TextEncoder().encode(ch.data.data.message), priv));
    const vf = await call(base, "POST", "/auth/verify", { address, nonce: ch.data.data.nonce, signature: sig });
    if (vf.status !== 200) throw new Error(`verify lỗi tại ${base}: ${JSON.stringify(vf.data)}`);
    return vf.data.data.token;
  };

  return { address, did, priv, pub, tokenTS: await login(TS), tokenGO: await login(GO) };
}

console.log("\n=== A. Tuyến công khai ===");
compare("GET /health", await call(TS, "GET", "/health"), await call(GO, "GET", "/health"),
  { compareShape: false });
compare("GET /stats", await call(TS, "GET", "/stats"), await call(GO, "GET", "/stats"));
compare("GET /lookup — định danh không hợp lệ",
  await call(TS, "GET", "/lookup?q=khong-hop-le"), await call(GO, "GET", "/lookup?q=khong-hop-le"));
compare("GET /lookup — thiếu tham số",
  await call(TS, "GET", "/lookup"), await call(GO, "GET", "/lookup"));
compare("GET /did/resolve — DID không tồn tại",
  await call(TS, "GET", "/did/resolve?did=did:vnu:holder:0x" + "9".repeat(64)),
  await call(GO, "GET", "/did/resolve?did=did:vnu:holder:0x" + "9".repeat(64)));

console.log("\n=== B. Kiểm tra dữ liệu vào ===");
const badInputs = [
  ["địa chỉ ví sai định dạng", "POST", "/entities/register",
    { address: "sai", publicKeyHex: "0x" + "a".repeat(64), did: "did:vnu:holder:0x1", role: "holder", label: "X" }],
  ["tự đăng ký vai trò root", "POST", "/entities/register",
    { address: "0x" + "1".repeat(64), publicKeyHex: "0x" + "a".repeat(64),
      did: "did:vnu:root:0x" + "1".repeat(64), role: "root", label: "X" }],
  ["vai trò không tồn tại", "POST", "/entities/register",
    { address: "0x" + "2".repeat(64), publicKeyHex: "0x" + "a".repeat(64),
      did: "did:vnu:holder:0x" + "2".repeat(64), role: "superuser", label: "X" }],
  ["DID không bám theo địa chỉ ví", "POST", "/entities/register",
    { address: "0x" + "3".repeat(64), publicKeyHex: "0x" + "a".repeat(64),
      did: "did:vnu:holder:0x" + "4".repeat(64), role: "holder", label: "X" }],
  ["tên hiển thị quá ngắn", "POST", "/entities/register",
    { address: "0x" + "5".repeat(64), publicKeyHex: "0x" + "a".repeat(64),
      did: "did:vnu:holder:0x" + "5".repeat(64), role: "holder", label: "X" }],
  ["challenge cho địa chỉ chưa đăng ký", "POST", "/auth/challenge", { address: "0x" + "7".repeat(64) }],
  ["chữ ký sai độ dài", "POST", "/auth/verify",
    { address: "0x" + "8".repeat(64), nonce: "abcdefgh", signature: "0xdeadbeef" }],
];
for (const [name, method, path, body] of badInputs) {
  compare(name, await call(TS, method, path, body), await call(GO, method, path, body));
}

console.log("\n=== C. Kiểm soát truy cập ===");
const authCases = [
  ["không có token", "GET", "/holder/credentials", null, null],
  ["token rác", "GET", "/holder/credentials", null, "khong-phai-jwt"],
  ["tuyến admin, không token", "GET", "/admin/overview", null, null],
  ["tuyến issuer, không token", "GET", "/issuer/stats", null, null],
];
for (const [name, method, path, body, tok] of authCases) {
  compare(name, await call(TS, method, path, body, tok), await call(GO, method, path, body, tok));
}

console.log("\n=== D. Phiên dùng chéo được giữa hai backend ===");
const holder = await makeActor("holder", "Nguoi so huu doi chieu");
rows.push({ name: "Tạo tài khoản ở TS rồi đăng nhập được ở cả hai", ok: !!(holder.tokenTS && holder.tokenGO) });
console.log(`  ${holder.tokenTS && holder.tokenGO ? "KHỚP" : "LỆCH"}  Tạo tài khoản ở TS rồi đăng nhập được ở cả hai`);

compare("GET /auth/me (mỗi bên dùng token của mình)",
  await call(TS, "GET", "/auth/me", null, holder.tokenTS),
  await call(GO, "GET", "/auth/me", null, holder.tokenGO));

// Token do TS cấp phải dùng được ở Go và ngược lại, vì chung JWT_SECRET.
const crossA = await call(GO, "GET", "/holder/credentials", null, holder.tokenTS);
const crossB = await call(TS, "GET", "/holder/credentials", null, holder.tokenGO);
const crossOK = crossA.status === 200 && crossB.status === 200;
rows.push({ name: "Token cấp bởi backend này dùng được ở backend kia", ok: crossOK });
console.log(`  ${crossOK ? "KHỚP" : "LỆCH"}  Token cấp bởi backend này dùng được ở backend kia  → TS→GO ${crossA.status}, GO→TS ${crossB.status}`);

compare("GET /holder/credentials",
  await call(TS, "GET", "/holder/credentials", null, holder.tokenTS),
  await call(GO, "GET", "/holder/credentials", null, holder.tokenGO));
compare("GET /holder/shares",
  await call(TS, "GET", "/holder/shares", null, holder.tokenTS),
  await call(GO, "GET", "/holder/shares", null, holder.tokenGO));
compare("GET /issuer/stats với vai trò holder → 403",
  await call(TS, "GET", "/issuer/stats", null, holder.tokenTS),
  await call(GO, "GET", "/issuer/stats", null, holder.tokenGO));

console.log("\n=== E. Không tin dữ liệu client ===");
const fakeTx = "0x" + "ab".repeat(32);
const doc = { "@context": ["https://www.w3.org/ns/did/v1"], id: holder.did };
const pinTS = await call(TS, "POST", "/ipfs/pin", { json: doc, name: "doi-chieu" }, holder.tokenTS);
const pinGO = await call(GO, "POST", "/ipfs/pin", { json: doc, name: "doi-chieu" }, holder.tokenGO);
compare("POST /ipfs/pin", pinTS, pinGO);

// Chế độ mock sinh CID tất định từ nội dung -> hai backend phải cho CÙNG một CID.
const sameCID = pinTS.data?.data?.cid === pinGO.data?.data?.cid;
rows.push({ name: "CID chế độ mock giống nhau ở hai backend", ok: sameCID });
console.log(`  ${sameCID ? "KHỚP" : "LỆCH"}  CID chế độ mock giống nhau ở hai backend  → TS=${pinTS.data?.data?.cid?.slice(0,20)}… GO=${pinGO.data?.data?.cid?.slice(0,20)}…`);

// Mỗi actor phải ghim ĐÚNG tài liệu của chính mình rồi khai hash của chính tài
// liệu đó. Dùng chung một CID cho hai tài liệu khác nhau thì integrityOk luôn
// false — và bài kiểm sẽ "đạt" vì một lý do chẳng liên quan gì tới điều nó định
// chứng minh.
async function mkSaveBody(a, base, token) {
  const docA = { "@context": ["https://www.w3.org/ns/did/v1"], id: a.did };
  const pin = await call(base, "POST", "/ipfs/pin", { json: docA, name: "doi-chieu" }, token);
  return {
    did: a.did,
    documentCid: pin.data?.data?.cid ?? "bafkrei" + "a".repeat(52),
    documentHash: hex(sha3_256(new TextEncoder().encode(JSON.stringify(docA)))),
    docJson: docA,
    txHash: fakeTx,
  };
}

// Hai backend dùng CHUNG một CSDL, nên không thể ghi cùng một DID ở cả hai rồi
// đòi kết quả giống nhau — bên sau sẽ đụng ràng buộc UNIQUE. Mỗi bên phải có
// một tài khoản riêng thì phép đối chiếu mới nói lên điều gì.
const saverTS = await makeActor("holder", "Nguoi ghi DID phia TS");
const saverGO = await makeActor("holder", "Nguoi ghi DID phia GO");
const bodyTS = await mkSaveBody(saverTS, TS, saverTS.tokenTS);
const bodyGO = await mkSaveBody(saverGO, GO, saverGO.tokenGO);
compare("POST /did/save với txHash bịa (kết quả tuỳ VERIFY_ONCHAIN)",
  await call(TS, "POST", "/did/save", bodyTS, saverTS.tokenTS),
  await call(GO, "POST", "/did/save", bodyGO, saverGO.tokenGO));
compare("POST /did/save với CID rỗng → bị từ chối",
  await call(TS, "POST", "/did/save", { ...bodyTS, documentCid: "" }, saverTS.tokenTS),
  await call(GO, "POST", "/did/save", { ...bodyGO, documentCid: "" }, saverGO.tokenGO));

// Nội dung ghim qua backend NÀY phải đọc được ở backend KIA. Trước đây kho mock
// nằm trong bộ nhớ từng tiến trình, nên nội dung ghim qua TS thì Go không thấy
// (và mất sạch sau mỗi lần khởi động lại) — hệ quả là mọi DID cũ resolve ra
// integrityOk: null, tức "không kiểm được toàn vẹn" cho đúng thứ hệ thống sinh
// ra để bảo đảm. Nay kho mock nằm trong CSDL dùng chung.
const didTS = await call(TS, "GET", `/did/resolve?did=${encodeURIComponent(saverTS.did)}`);
const didGO = await call(GO, "GET", `/did/resolve?did=${encodeURIComponent(saverTS.did)}`);
compare("GET /did/resolve — DID ghim ở TS, đọc ở cả hai", didTS, didGO);
const crossIntegrity =
  didTS.data?.data?.integrityOk === true && didGO.data?.data?.integrityOk === true;
rows.push({ name: "Toàn vẹn tài liệu DID kiểm được ở CẢ HAI backend", ok: crossIntegrity });
console.log(`  ${crossIntegrity ? "KHỚP" : "LỆCH"}  Toàn vẹn tài liệu DID kiểm được ở CẢ HAI backend` +
  `  → TS integrityOk=${didTS.data?.data?.integrityOk}, GO integrityOk=${didGO.data?.data?.integrityOk}`);

console.log("\n=== F. Quản trị quyền hạn trên chuỗi ===");
// Tuyến mới thêm cùng lúc ở hai backend. Không đối chiếu là cách chắc chắn
// nhất để chúng lệch nhau ngay từ ngày đầu.
const authorityGuards = [
  ["GET /admin/authority/root — không token", "GET", "/admin/authority/root", null, null],
  ["GET /admin/authority/root — vai trò holder → 403", "GET", "/admin/authority/root", null, "HOLDER"],
  ["GET /admin/authority/role/{addr} — vai trò holder → 403",
    "GET", "/admin/authority/role/0x" + "1".repeat(64), null, "HOLDER"],
  ["POST /admin/authority/admins — vai trò holder → 403", "POST", "/admin/authority/admins",
    { address: "0x" + "1".repeat(64), txHash: fakeTx }, "HOLDER"],
  ["POST /admin/authority/issuers — vai trò holder → 403", "POST", "/admin/authority/issuers",
    { address: "0x" + "1".repeat(64), vcTypeMask: 1, expiresAt: 0, txHash: fakeTx }, "HOLDER"],
  ["POST /admin/authority/root/propose — vai trò holder → 403", "POST", "/admin/authority/root/propose",
    { address: "0x" + "1".repeat(64), txHash: fakeTx }, "HOLDER"],
  // Tuyến nhận quyền root CỐ Ý không chặn theo vai trò: người được đề cử lúc
  // đó chưa phải root. Nó phải thất bại ở bước xác minh giao dịch, không phải 403.
  ["POST /authority/root/accept — không token", "POST", "/authority/root/accept",
    { txHash: fakeTx }, null],
  ["GET /authority/root — holder đọc được (không chặn vai trò)", "GET", "/authority/root", null, "HOLDER"],
];
for (const [name, method, path, body, who] of authorityGuards) {
  const tsTok = who === "HOLDER" ? holder.tokenTS : who;
  const goTok = who === "HOLDER" ? holder.tokenGO : who;
  compare(name, await call(TS, method, path, body, tsTok), await call(GO, method, path, body, goTok));
}

// Dữ liệu vào sai phải bị TỪ CHỐI GIỐNG NHAU ở cả hai, kể cả khi người gọi
// đúng vai trò — đây là chỗ hai bản cài đặt hay lệch thứ tự kiểm tra nhất.
const adminActor = await makeActor("admin", "Quan tri vien doi chieu");
const authorityInputs = [
  ["địa chỉ sai định dạng khi cấp admin", "POST", "/admin/authority/admins",
    { address: "khong-phai-dia-chi", txHash: fakeTx }],
  ["txHash sai định dạng khi cấp admin", "POST", "/admin/authority/admins",
    { address: "0x" + "1".repeat(64), txHash: "0xngan" }],
  ["vcTypeMask ngoài khoảng cho phép", "POST", "/admin/authority/issuers",
    { address: "0x" + "1".repeat(64), vcTypeMask: 999, expiresAt: 0, txHash: fakeTx }],
  ["vcTypeMask bằng 0", "POST", "/admin/authority/issuers",
    { address: "0x" + "1".repeat(64), vcTypeMask: 0, expiresAt: 0, txHash: fakeTx }],
  ["hạn uỷ quyền đã ở quá khứ", "POST", "/admin/authority/issuers",
    { address: "0x" + "1".repeat(64), vcTypeMask: 1, expiresAt: 1000, txHash: fakeTx }],
  ["trạng thái issuer không hợp lệ", "POST", `/admin/authority/issuers/0x${"1".repeat(64)}/status`,
    { status: "khong-ton-tai", reason: "thu nghiem", txHash: fakeTx }],
  ["lý do quá ngắn khi đổi trạng thái issuer", "POST", `/admin/authority/issuers/0x${"1".repeat(64)}/status`,
    { status: "revoked", reason: "x", txHash: fakeTx }],
  // Hai phép dưới dừng ở rào "chỉ root" (403) chứ chưa chạm tới phần kiểm tra
  // địa chỉ — điều cần đối chiếu là CẢ HAI dừng ở cùng một chỗ, cùng một mã.
  ["admin (không phải root) không đề cử được root — chính mình", "POST", "/admin/authority/root/propose",
    { address: adminActor.address, txHash: fakeTx }],
  ["admin (không phải root) không đề cử được root — địa chỉ lạ", "POST", "/admin/authority/root/propose",
    { address: "0x" + "c".repeat(64), txHash: fakeTx }],
];
for (const [name, method, path, body] of authorityInputs) {
  compare(name, await call(TS, method, path, body, adminActor.tokenTS),
    await call(GO, method, path, body, adminActor.tokenGO));
}

// Ảnh chụp quyền của một địa chỉ có thật phải cùng hình dạng ở hai bên.
compare("GET /admin/authority/role/{addr} — địa chỉ có thật",
  await call(TS, "GET", `/admin/authority/role/${adminActor.address}`, null, adminActor.tokenTS),
  await call(GO, "GET", `/admin/authority/role/${adminActor.address}`, null, adminActor.tokenGO));
compare("GET /admin/authority/root — admin đọc được",
  await call(TS, "GET", "/admin/authority/root", null, adminActor.tokenTS),
  await call(GO, "GET", "/admin/authority/root", null, adminActor.tokenGO));

console.log("\n=== G. Trường lạ trong thân yêu cầu ===");
// Lệch THẬT từng bắt được ở đây: zod mặc định BỎ QUA trường lạ còn encoding/json
// bên Go (DisallowUnknownFields) thì TỪ CHỐI — cùng một yêu cầu, TS trả 201 còn
// Go trả 400. Hai bên nay đều nghiêm ngặt. Gõ nhầm `expireAt` thay vì
// `expiresAt` phải báo lỗi ngay, chứ không lặng lẽ cấp văn bằng vĩnh viễn.
const unknownFieldCases = [
  ["đăng ký thực thể kèm trường lạ", "POST", "/entities/register",
    { address: "0x" + "d".repeat(64), publicKeyHex: "0x" + "a".repeat(64),
      did: "did:vnu:holder:0x" + "d".repeat(64), role: "holder",
      label: "Kiem thu truong la", truongLa: "gia tri thua" }, null],
  ["xin challenge kèm trường lạ", "POST", "/auth/challenge",
    { address: "0x" + "d".repeat(64), themGiDo: 1 }, null],
  ["tạo bản trình bày kèm trường lạ", "POST", "/holder/presentations",
    { vpId: "urn:uuid:khong-quan-trong", vcIds: ["urn:uuid:x-khong-quan-trong"],
      ipfsCid: "bafkrei" + "a".repeat(52), vpHash: "0x" + "b".repeat(64),
      proofValue: "0x" + "c".repeat(128), vpJson: { thua: true } }, "HOLDER"],
  ["đổi trạng thái VC kèm trường lạ", "POST", "/issuer/credentials/khong-ton-tai/revoke",
    { reason: "thu nghiem", txHash: fakeTx, themTruong: "x" }, "HOLDER"],
];
for (const [name, method, path, body, who] of unknownFieldCases) {
  const tsTok = who === "HOLDER" ? holder.tokenTS : who;
  const goTok = who === "HOLDER" ? holder.tokenGO : who;
  compare(name, await call(TS, method, path, body, tsTok), await call(GO, method, path, body, goTok));
}

console.log("\n=== H. Liên kết chia sẻ ===");
compare("GET /verify/share/{token} không tồn tại",
  await call(TS, "GET", "/verify/share/khong-ton-tai-gi-ca"),
  await call(GO, "GET", "/verify/share/khong-ton-tai-gi-ca"));
compare("POST /verify/share/{token} không tồn tại",
  await call(TS, "POST", "/verify/share/khong-ton-tai-gi-ca"),
  await call(GO, "POST", "/verify/share/khong-ton-tai-gi-ca"));

console.log("\n=== I. Tra một văn bằng theo mã ===");
// Ba tuyến này từng CHỈ CÓ ở bản TypeScript: bản Go không đăng ký route nên
// cùng một yêu cầu cho 404-của-router thay vì 403/404-của-nghiệp-vụ. Giao diện
// quản trị cần chúng để đọc số hiệu on-chain của văn bằng trước khi ký giao
// dịch cưỡng chế, nên chỗ lệch này đã thành lỗi thật chứ không còn là lý thuyết.
const vcLookupCases = [
  ["GET /holder/credentials/{vcId} — không tồn tại", "/holder/credentials/urn:uuid:khong-ton-tai", "HOLDER"],
  ["GET /issuer/credentials/{vcId} — vai trò holder → 403", "/issuer/credentials/urn:uuid:khong-ton-tai", "HOLDER"],
  ["GET /admin/credentials/{vcId} — vai trò holder → 403", "/admin/credentials/urn:uuid:khong-ton-tai", "HOLDER"],
  ["GET /admin/credentials/{vcId} — admin, mã không tồn tại", "/admin/credentials/urn:uuid:khong-ton-tai", "ADMIN"],
  ["GET /admin/credentials/{vcId} — không token", "/admin/credentials/urn:uuid:khong-ton-tai", null],
];
for (const [name, path, who] of vcLookupCases) {
  const tsTok = who === "HOLDER" ? holder.tokenTS : who === "ADMIN" ? adminActor.tokenTS : who;
  const goTok = who === "HOLDER" ? holder.tokenGO : who === "ADMIN" ? adminActor.tokenGO : who;
  compare(name, await call(TS, "GET", path, null, tsTok), await call(GO, "GET", path, null, goTok));
}

console.log("\n=== J. Tra theo địa chỉ và số liệu biểu đồ ===");
// Hai tuyến by-address từng chỉ có ở bản TS: giao diện khôi phục ví và thẻ DID
// gãy ngay khi đổi sang Go.
const byAddrCases = [
  ["GET /entities/by-address — đã đăng ký", `/entities/by-address/${holder.address}`, null],
  ["GET /entities/by-address — chưa đăng ký", `/entities/by-address/0x${"6".repeat(64)}`, null],
  ["GET /did/by-address — chưa có DID", `/did/by-address/0x${"6".repeat(64)}`, null],
  ["GET /issuer/stats — vai trò holder → 403", "/issuer/stats", "HOLDER"],
  ["GET /admin/analytics — admin", "/admin/analytics", "ADMIN"],
  ["GET /admin/analytics — vai trò holder → 403", "/admin/analytics", "HOLDER"],
];
for (const [name, path, who] of byAddrCases) {
  const tsTok = who === "HOLDER" ? holder.tokenTS : who === "ADMIN" ? adminActor.tokenTS : who;
  const goTok = who === "HOLDER" ? holder.tokenGO : who === "ADMIN" ? adminActor.tokenGO : who;
  compare(name, await call(TS, "GET", path, null, tsTok), await call(GO, "GET", path, null, goTok));
}

// ---- Đợt rà soát bảo mật (docs/SECURITY_REVIEW.md): mỗi hành vi mới phải giống nhau ở hai bên.
async function callRaw(base, method, path, raw) {
  const r = await fetch(base + path, { method, headers: { "content-type": "application/json" }, body: raw });
  return { status: r.status, data: await r.json().catch(() => null) };
}
{
  // S-01: địa chỉ không khớp khoá công khai; địa chỉ chữ hoa được chuẩn hoá.
  const p1 = ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
  const other = "0x" + "7".repeat(64);
  const bad = { address: other, publicKeyHex: hex(p1), did: `did:vnu:holder:${other}`, role: "holder", label: "Mạo danh" };
  compare("S-01 đăng ký địa chỉ không khớp khoá công khai → 400",
    await call(TS, "POST", "/entities/register", bad), await call(GO, "POST", "/entities/register", bad));

  // S-03: tra CID của nội dung không phải DID Document → không trả nội dung.
  const pinBody = { json: { credentialSubject: { "vnu:studentId": "SV-PARITY" } }, name: "vc" };
  const cTS = (await call(TS, "POST", "/ipfs/pin", pinBody, holder.tokenTS)).data?.data?.cid;
  const lTS = await call(TS, "GET", `/lookup?q=${cTS}`), lGO = await call(GO, "GET", `/lookup?q=${cTS}`);
  compare("S-03 GET /lookup — CID văn bằng (riêng tư)", lTS, lGO);
  const noLeak = ![lTS, lGO].some((r) => JSON.stringify(r.data).includes("SV-PARITY"));
  rows.push({ name: "S-03 không bên nào lộ nội dung văn bằng qua /lookup", ok: noLeak });
  console.log(`  ${noLeak ? "KHỚP" : "LỆCH"}  S-03 không bên nào lộ nội dung văn bằng qua /lookup`);

  // P-05: hồ sơ công khai không có tên hiển thị.
  const eTS = await call(TS, "GET", `/entities/by-address/${holder.address}`);
  const eGO = await call(GO, "GET", `/entities/by-address/${holder.address}`);
  const noLabel = eTS.data?.data?.label === null && eGO.data?.data?.label === null;
  rows.push({ name: "P-05 /entities/by-address trả label = null ở cả hai bên", ok: noLabel });
  console.log(`  ${noLabel ? "KHỚP" : "LỆCH"}  P-05 /entities/by-address trả label = null ở cả hai bên`);

  // S-07, L-02, L-03: dung lượng ghim, thân hỏng, thân quá lớn, NUL.
  const big = { json: { x: "a".repeat(300 * 1024) }, name: "lon" };
  compare("S-07 POST /ipfs/pin 300KB → 413",
    await call(TS, "POST", "/ipfs/pin", big, holder.tokenTS), await call(GO, "POST", "/ipfs/pin", big, holder.tokenGO));
  compare("L-02 JSON hỏng → 400",
    await callRaw(TS, "POST", "/auth/challenge", "{hỏng"), await callRaw(GO, "POST", "/auth/challenge", "{hỏng"));
  const huge = JSON.stringify({ address: "0x" + "a".repeat(3 * 1024 * 1024) });
  compare("L-02 thân > 2MB → 413",
    await callRaw(TS, "POST", "/auth/challenge", huge), await callRaw(GO, "POST", "/auth/challenge", huge));
  const nul = JSON.stringify({ address: "0x1\u0000" });
  compare("L-03 chuỗi chứa NUL → 400",
    await callRaw(TS, "POST", "/auth/challenge", nul), await callRaw(GO, "POST", "/auth/challenge", nul));

  // L-05: lọc trạng thái và phân trang không hợp lệ.
  const iss = await makeActor("issuer", "Đơn vị đối chiếu");
  compare("L-05 GET /issuer/credentials?status=sai → 400",
    await call(TS, "GET", "/issuer/credentials?status=sai", null, iss.tokenTS),
    await call(GO, "GET", "/issuer/credentials?status=sai", null, iss.tokenGO));
  compare("L-05 GET /issuer/credentials?status=active",
    await call(TS, "GET", "/issuer/credentials?status=active", null, iss.tokenTS),
    await call(GO, "GET", "/issuer/credentials?status=active", null, iss.tokenGO));
  compare("L-05 GET /admin/audit?limit=100000 → 400",
    await call(TS, "GET", "/admin/audit?limit=100000", null, adminActor.tokenTS),
    await call(GO, "GET", "/admin/audit?limit=100000", null, adminActor.tokenGO));
  compare("L-05 GET /admin/issuers?offset=-1 → 400",
    await call(TS, "GET", "/admin/issuers?offset=-1", null, adminActor.tokenTS),
    await call(GO, "GET", "/admin/issuers?offset=-1", null, adminActor.tokenGO));
}

// Giao diện bật/tắt màn hình uỷ quyền theo cờ này, nên thiếu ở một bên là giao
// diện đổi hành vi chỉ vì người dùng chọn backend khác ở thanh trên.
const meTS = await call(TS, "GET", "/auth/me", null, holder.tokenTS);
const meGO = await call(GO, "GET", "/auth/me", null, holder.tokenGO);
const bothCanDelegate =
  typeof meTS.data?.data?.onChain?.canDelegate === "boolean" &&
  typeof meGO.data?.data?.onChain?.canDelegate === "boolean";
rows.push({ name: "/auth/me trả canDelegate ở cả hai backend", ok: bothCanDelegate });
console.log(`  ${bothCanDelegate ? "KHỚP" : "LỆCH"}  /auth/me trả canDelegate ở cả hai backend` +
  `  → TS=${meTS.data?.data?.onChain?.canDelegate}, GO=${meGO.data?.data?.onChain?.canDelegate}`);

console.log("\n=== K. Logic hợp đồng 13/11/2026: kiểm duyệt DID, uỷ quyền, tạm ngưng của admin ===");
// Tuyến mới thêm cùng lúc ở hai backend (bài học #22). Hợp đồng đòi admin và
// issuer có DID ACTIVE, nên actor ở đây phải ghi DID thật — admin không DID thì
// mọi tuyến kiểm quyền on-chain dừng ở 403 và phép đối chiếu chẳng chứng minh gì.
async function withDid(a) {
  const body = await mkSaveBody(a, TS, a.tokenTS);
  const r = await call(TS, "POST", "/did/save", body, a.tokenTS);
  if (r.status !== 201 && r.status !== 200) throw new Error(`ghi DID lỗi: ${JSON.stringify(r.data)}`);
  return a;
}
const live = (await call(TS, "GET", "/health")).data?.data?.verifyOnChain !== false;
const modAdmin = await withDid(await makeActor("admin", "Admin kiem duyet"));
const otherAdmin = await withDid(await makeActor("admin", "Admin khac"));
const issTS = await withDid(await makeActor("issuer", "Issuer phia TS"));
const issGO = await withDid(await makeActor("issuer", "Issuer phia GO"));
const tgtTS = await withDid(await makeActor("holder", "Dich kiem duyet TS"));
const tgtGO = await withDid(await makeActor("holder", "Dich kiem duyet GO"));

const didStatus = (st, reason = "Kiem duyet doi chieu") => ({ status: st, reason, txHash: fakeTx });
const pairs = [
  ["POST /admin/dids/{addr}/status — vai trò holder → 403",
    [TS, `/admin/dids/${tgtTS.address}/status`, didStatus("suspended"), holder.tokenTS],
    [GO, `/admin/dids/${tgtGO.address}/status`, didStatus("suspended"), holder.tokenGO]],
  ["POST /admin/dids/{addr}/status — trạng thái lạ → 400",
    [TS, `/admin/dids/${tgtTS.address}/status`, didStatus("xoa"), modAdmin.tokenTS],
    [GO, `/admin/dids/${tgtGO.address}/status`, didStatus("xoa"), modAdmin.tokenGO]],
  ["POST /admin/dids/{addr}/status — lý do quá ngắn → 400",
    [TS, `/admin/dids/${tgtTS.address}/status`, didStatus("suspended", "x"), modAdmin.tokenTS],
    [GO, `/admin/dids/${tgtGO.address}/status`, didStatus("suspended", "x"), modAdmin.tokenGO]],
  ["POST /admin/dids/{addr}/status — kèm trường lạ → 400",
    [TS, `/admin/dids/${tgtTS.address}/status`, { ...didStatus("suspended"), thua: 1 }, modAdmin.tokenTS],
    [GO, `/admin/dids/${tgtGO.address}/status`, { ...didStatus("suspended"), thua: 1 }, modAdmin.tokenGO]],
  ["POST /admin/dids/{addr}/status — admin khoá DID của holder",
    [TS, `/admin/dids/${tgtTS.address}/status`, didStatus("suspended"), modAdmin.tokenTS],
    [GO, `/admin/dids/${tgtGO.address}/status`, didStatus("suspended"), modAdmin.tokenGO]],
  ["POST /admin/dids/{addr}/status — admin thường khoá DID admin khác → 403 (offline) / chuỗi chặn",
    [TS, `/admin/dids/${otherAdmin.address}/status`, didStatus("suspended"), modAdmin.tokenTS],
    [GO, `/admin/dids/${otherAdmin.address}/status`, didStatus("suspended"), modAdmin.tokenGO]],
  ["POST /admin/dids/{addr}/status — thu hồi DID của issuer (M-01)",
    [TS, `/admin/dids/${issTS.address}/status`, didStatus("revoked"), modAdmin.tokenTS],
    [GO, `/admin/dids/${issGO.address}/status`, didStatus("revoked"), modAdmin.tokenGO]],
  ["POST /admin/credentials/{vcId}/suspend — vai trò holder → 403",
    [TS, "/admin/credentials/urn:uuid:khong-ton-tai/suspend", { reason: "thu nghiem", txHash: fakeTx }, holder.tokenTS],
    [GO, "/admin/credentials/urn:uuid:khong-ton-tai/suspend", { reason: "thu nghiem", txHash: fakeTx }, holder.tokenGO]],
  ["POST /admin/credentials/{vcId}/suspend — admin, mã không tồn tại",
    [TS, "/admin/credentials/urn:uuid:khong-ton-tai/suspend", { reason: "thu nghiem", txHash: fakeTx }, modAdmin.tokenTS],
    [GO, "/admin/credentials/urn:uuid:khong-ton-tai/suspend", { reason: "thu nghiem", txHash: fakeTx }, modAdmin.tokenGO]],
  ["POST /admin/authority/admins/{addr}/revoke — kèm trường status thừa → 400",
    [TS, `/admin/authority/admins/${otherAdmin.address}/revoke`, { reason: "thu nghiem", txHash: fakeTx, status: "revoked" }, modAdmin.tokenTS],
    [GO, `/admin/authority/admins/${otherAdmin.address}/revoke`, { reason: "thu nghiem", txHash: fakeTx, status: "revoked" }, modAdmin.tokenGO]],
];
for (const [name, [b1, p1, body1, t1], [b2, p2, body2, t2]] of pairs) {
  compare(name, await call(b1, "POST", p1, body1, t1), await call(b2, "POST", p2, body2, t2));
}

// Sau khi kiểm duyệt, chỉ mục ở hai bên phải phản ánh đúng điều hợp đồng làm.
if (!live) {
  const sTS = (await call(TS, "GET", `/did/by-address/${tgtTS.address}`)).data?.data?.status;
  const sGO = (await call(GO, "GET", `/did/by-address/${tgtGO.address}`)).data?.data?.status;
  const okSusp = sTS === "suspended" && sGO === "suspended";
  rows.push({ name: "DID bị admin khoá đọc ra 'suspended' ở cả hai", ok: okSusp });
  console.log(`  ${okSusp ? "KHỚP" : "LỆCH"}  DID bị admin khoá đọc ra 'suspended' ở cả hai  → TS=${sTS}, GO=${sGO}`);
  const rTS = (await call(TS, "GET", `/entities/by-address/${issTS.address}`)).data?.data?.role;
  const rGO = (await call(GO, "GET", `/entities/by-address/${issGO.address}`)).data?.data?.role;
  const okM01 = rTS === "holder" && rGO === "holder";
  rows.push({ name: "M-01: thu hồi DID hạ vai trò issuer về holder ở cả hai", ok: okM01 });
  console.log(`  ${okM01 ? "KHỚP" : "LỆCH"}  M-01: thu hồi DID hạ vai trò issuer về holder ở cả hai  → TS=${rTS}, GO=${rGO}`);
}

// Uỷ quyền: quan hệ cha–con chỉ tồn tại trên chuỗi, nên chế độ offline từ chối
// thẳng thay vì đoán (cùng tinh thần canDelegateOffline).
const delegator = await withDid(await makeActor("issuer", "Issuer uy quyen"));
const delegCases = [
  ["GET /issuer/delegation — issuer", "GET", "/issuer/delegation", null, delegator],
  ["GET /issuer/delegation — vai trò holder → 403", "GET", "/issuer/delegation", null, holder],
  ["POST /issuer/sub-issuers — bit uỷ quyền → 400", "POST", "/issuer/sub-issuers",
    { address: tgtTS.address, vcTypeMask: 33, expiresAt: 0, txHash: fakeTx }, delegator],
  ["POST /issuer/sub-issuers — kèm trường lạ → 400", "POST", "/issuer/sub-issuers",
    { address: tgtTS.address, vcTypeMask: 1, expiresAt: 0, txHash: fakeTx, thua: 1 }, delegator],
  ["POST /issuer/sub-issuers — hợp lệ về hình thức", "POST", "/issuer/sub-issuers",
    { address: tgtTS.address, vcTypeMask: 1, expiresAt: 0, txHash: fakeTx }, delegator],
  ["POST /issuer/sub-issuers/{addr}/status — kích hoạt lại không được phép → 400", "POST",
    `/issuer/sub-issuers/${tgtTS.address}/status`, { status: "active", reason: "thu nghiem", txHash: fakeTx }, delegator],
  ["POST /issuer/sub-issuers/{addr}/status — tạm ngưng", "POST",
    `/issuer/sub-issuers/${tgtTS.address}/status`, { status: "suspended", reason: "thu nghiem", txHash: fakeTx }, delegator],
];
for (const [name, method, path, body, a] of delegCases) {
  compare(name, await call(TS, method, path, body, a.tokenTS), await call(GO, method, path, body, a.tokenGO));
}

// vc_type phải là đúng MỘT bit: hợp đồng từ chối "cử nhân + thạc sĩ" (3).
const vcIss = await withDid(await makeActor("issuer", "Issuer kiem loai van bang"));
const multiBit = {
  vcId: "urn:uuid:doi-chieu-nhieu-bit", onChainVcId: 1, holderDid: holder.did, holderAddress: holder.address,
  vcType: 3, ipfsCid: "bafkrei" + "a".repeat(52), vcIdHash: "0x" + "1".repeat(64), contentHash: "0x" + "2".repeat(64),
  proofValue: "0x" + "c".repeat(128), vcJson: { x: 1 }, issuedAt: new Date().toISOString(), expiresAt: null, txHash: fakeTx,
};
compare("POST /issuer/credentials — vcType nhiều bit → 400",
  await call(TS, "POST", "/issuer/credentials", multiBit, vcIss.tokenTS),
  await call(GO, "POST", "/issuer/credentials", multiBit, vcIss.tokenGO));

const failed = rows.filter((r) => !r.ok);
console.log(`\n${rows.length - failed.length}/${rows.length} KHỚP` +
  (failed.length ? `  — ${failed.length} LỆCH:\n  ${failed.map((f) => f.name).join("\n  ")}` : "  — hai backend tương đương"));
process.exit(failed.length ? 1 : 0);
